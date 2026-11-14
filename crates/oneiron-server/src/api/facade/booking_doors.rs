//! Typed booking-page discovery, published lifecycle and constraint front.
use std::sync::Arc;

use oneiron::booking::agent_api::{BookingOperationRequest, BookingOperationResponse};
use oneiron::booking::{PersonalBookingLink, PersonalLinkEndReason, PersonalLinkRecipient};
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    BookingAvailabilityRequest, BookingBookRequest, BookingCancelRequest,
    BookingConstraintTurnRequest, BookingConstraintTurnResponse, BookingPageTokenRequest,
    BookingPageTokenResponse, BookingPersonalLink, BookingPersonalLinkListRequest,
    BookingPersonalLinkListResponse, BookingPersonalLinkMintRequest,
    BookingPersonalLinkMintResponse, BookingPersonalLinkRevokeRequest,
    BookingPersonalLinkRevokeResponse, BookingRescheduleRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::FacadeApiError;
use super::host_doors::support::{
    Listed, MaybeListed, credential_listing, internal, owner_proof, refused,
};
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

/// The owner mints a personal link to one of their published pages for one
/// recipient (BK-PERSONAL-LINKS). The same owner proof as every owner door;
/// the engine door then checks the owner as a live actor with live
/// authority and the page as published. The raw token is answered once.
pub(crate) async fn vault_booking_personal_link_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingPersonalLinkMintRequest,
) -> Listed<BookingPersonalLinkMintResponse> {
    as_booking_owner(
        server,
        auth,
        "vault.booking.personal_link.mint",
        move |memory| {
            let page_ref = parse_page_ref(&input.page_ref)?;
            let minted = memory.mint_personal_booking_link(
                page_ref,
                &PersonalLinkRecipient {
                    email: input.recipient_email,
                    name: input.recipient_name,
                },
            )?;
            Ok(BookingPersonalLinkMintResponse {
                link: personal_link_view(&minted.link),
                token: minted.token,
            })
        },
    )
    .await
}

/// The owner ends one personal link: a lost or mis-sent link is revoked and,
/// if still wanted, minted again.
pub(crate) async fn vault_booking_personal_link_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingPersonalLinkRevokeRequest,
) -> Listed<BookingPersonalLinkRevokeResponse> {
    as_booking_owner(
        server,
        auth,
        "vault.booking.personal_link.revoke",
        move |memory| {
            let revoked = memory.revoke_personal_booking_link(input.link_ref.trim())?;
            Ok(BookingPersonalLinkRevokeResponse { revoked })
        },
    )
    .await
}

/// The owner reads every personal link of one page, live and ended, with
/// why each ended: a "not you?" shows here as well as in its notice.
pub(crate) async fn vault_booking_personal_link_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingPersonalLinkListRequest,
) -> Listed<BookingPersonalLinkListResponse> {
    as_booking_owner(
        server,
        auth,
        "vault.booking.personal_link.list",
        move |memory| {
            let page_ref = parse_page_ref(&input.page_ref)?;
            let links = memory.personal_booking_links(page_ref)?;
            Ok(BookingPersonalLinkListResponse {
                links: links.iter().map(personal_link_view).collect(),
            })
        },
    )
    .await
}

/// One owner door's act on the owner's own credential handle, off the
/// runtime, as `calendar_doors`' owner doors run theirs.
async fn as_booking_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let actor = match owner.actor_for_read(server.vault()) {
        Ok(actor) => actor,
        Err(error) => return refused(error.into()),
    };
    credential_listing(
        server,
        auth,
        (actor, EdgeActorClass::Human),
        verb,
        move |_, _, memory| act(memory),
    )
    .await
}

fn parse_page_ref(page_ref: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(page_ref.trim())
        .map_err(|_| MemoryError::bad_request("invalid booking page_ref"))
}

fn personal_link_view(link: &PersonalBookingLink) -> BookingPersonalLink {
    BookingPersonalLink {
        link_ref: link.link_ref.clone(),
        page_ref: link.page_ref.to_hex(),
        recipient_email: link.recipient.email.clone(),
        recipient_name: link.recipient.name.clone(),
        minted_at: link.minted_at,
        ended_at: link.ended.map(|end| end.at),
        ended_reason: link.ended.map(|end| {
            match end.reason {
                PersonalLinkEndReason::NotRecipient => "not_recipient",
                PersonalLinkEndReason::Revoked => "revoked",
            }
            .to_owned()
        }),
    }
}
