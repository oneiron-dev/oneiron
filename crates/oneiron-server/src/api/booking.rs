//! ONE-1819 [BK-08] the agent-readable booking surface.
//!
//! One executor, two transports. [`execute_booking_operation`] is the ONLY
//! path from a machine-readable booking request to the merged solver and the
//! merged lifecycle; the public HTTP routes below and the MCP `oneiron.book`
//! adapter are thin shells over it, so validation, admission, parsing,
//! dispatch, and response projection cannot drift between them.
//!
//! Three invariants are enforced here and nowhere else:
//!
//! * **One admission call.** The ONE-1817 guard runs exactly once, inside the
//!   executor, before the parser, the oracle, or the lifecycle is touched.
//!   Neither the HTTP handlers nor the MCP gateway pre-check it, and neither
//!   can: the guard call sites are private to this module.
//! * **Opaque tokens only.** A caller addresses a page by `page_token` and a
//!   booking by the action-scoped token the lifecycle minted. The
//!   `EntityId` -> token direction is a one-way digest; the token -> `EntityId`
//!   direction resolves only in this file, against booking pages the vault
//!   already carries.
//! * **Adapter, never a parallel writer.** Every mutation is enqueued as a
//!   lifecycle verb and executed by the home-node writer, which revalidates
//!   the slot against committed state. Idempotency keys are replay hygiene. A
//!   hold first asks the page's own oracle whether the slot is offerable at
//!   all, so an invented slot never reaches a lifecycle credential — a read
//!   that refuses, never a second opinion about what is writable.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};

use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_MIME, BookingAvailabilityInput, BookingBookInput, BookingBookResult,
    BookingCancelInput, BookingConfirmInput, BookingConstraintInput, BookingHoldInput,
    BookingOperationRequest, BookingOperationResponse, BookingRescheduleInput, SelectedSlot,
};
use oneiron::booking::{
    BookingError, BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmSpec,
    ConstraintObject, HoldLeaseSpec, HoldSpec, OpaqueCheckoutLeaseToken, OpaqueLifecycleToken,
    RescheduleSpec, SlotOracle, SolveRequest, SolveResult, token_page_ref,
};
use oneiron::{EntityId, Vault};

use super::booking_anti_abuse::{enforce_book, enforce_hold, enforce_slot_list};
use super::{check_api_auth, json_payload};
use crate::error::ApiError;
use crate::server::SyncServer;

mod admission;
mod constants;
mod helpers;
mod instructions;
mod lifecycle;
mod offerability;
mod page_token;
mod subject;
mod transport;
mod validate;

use self::admission::{admission_facts, admission_short_circuit};
pub(crate) use self::constants::BOOKING_ROUTE_PREFIX;
use self::helpers::{booking_error, now_secs, slot_range};
pub(crate) use self::instructions::{
    booking_agent_instructions_block, booking_agent_instructions_json,
    render_booking_agent_instructions_block,
};
use self::lifecycle::{booking_oracle, run_booking_verb};
use self::offerability::unoffered_slot_answer;
pub(crate) use self::page_token::{booking_page_token, resolve_booking_page};
use self::subject::{resolve_booker_contact, session_key};
use self::transport::http_transport_context;
use self::validate::validate_operation_shape;

// The pre-split root path stays callable. Minting and resolution both live in
// `page_token` now, so the re-exported minter has no second call site in this
// crate; binding it once at compile time keeps
// `crate::api::booking::booking_page_token` an item of the same name,
// visibility, and signature it had before the split, with no allow attribute
// and no runtime effect.
const _: fn(EntityId) -> String = booking_page_token;

// -------------------------------------------------------------------------
// Route shape
// -------------------------------------------------------------------------

/// Which transport carried one booking request.
///
/// The variant changes nothing about admission, parsing, solving, or the
/// lifecycle: it exists so logs and the MCP result envelope can say which door
/// a request came through, and so a future transport has a name to add.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BookingTransport {
    PublicHttp,
    Mcp,
}

impl BookingTransport {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PublicHttp => "public_http",
            Self::Mcp => "mcp",
        }
    }
}

/// Server-derived request context.
///
/// Every field is derived on this side of the boundary. `authenticated_actor_ref`
/// is server-local: it is an internal identifier, it is never serialized into a
/// booking request or response, and a caller cannot supply one.
#[derive(Clone, Debug)]
pub(crate) struct BookingTransportContext {
    pub(crate) source_ip: IpAddr,
    pub(crate) authenticated_actor_ref: Option<EntityId>,
    pub(crate) transport: BookingTransport,
}

impl BookingTransportContext {
    /// The actor key mixed into admission. An authenticated connector actor
    /// keys its own budget; an owner-bearer HTTP caller keys on the source
    /// address alone, exactly as the MCP door would with no actor.
    fn actor_key(&self) -> Option<String> {
        self.authenticated_actor_ref.as_ref().map(EntityId::to_hex)
    }
}

/// The booking resource router.
///
/// Every handler threads `State<Arc<SyncServer>>` and returns
/// `crate::error::ApiError`. This surface introduces no second application
/// state type, no vault wrapper, and no write-principal type of its own: the
/// state a booking handler can reach is exactly the state every other resource
/// on this server reaches.
pub(crate) fn booking_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            "/api/booking/{page_token}/agent-instructions",
            get(booking_agent_instructions),
        )
        .route(
            "/api/booking/{page_token}/availability",
            post(booking_availability),
        )
        .route("/api/booking/{page_token}/book", post(booking_book))
        .route(
            "/api/booking/{page_token}/reschedule",
            post(booking_reschedule),
        )
        .route("/api/booking/{page_token}/cancel", post(booking_cancel))
}

// -------------------------------------------------------------------------
// HTTP handlers
// -------------------------------------------------------------------------

/// Returns the versioned instructions document for one booking page.
#[utoipa::path(
    get,
    path = "/api/booking/{page_token}/agent-instructions",
    params(
        ("page_token" = String, Path, description = "Opaque booking page token. It encodes no internal identifier and resolves only server-side.")
    ),
    responses(
        (
            status = 200,
            description = "Versioned booking instructions document, byte-equivalent to the JSON embedded by the public page fragment. Request `Accept: text/html` for the embeddable script-safe fragment carrying the same document.",
            body = Object,
            content_type = "application/vnd.oneiron.booking-agent+json"
        ),
        (
            status = 401,
            description = "Missing or invalid bearer credentials.",
            body = ApiError,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "No booking page resolves from this token.",
            body = ApiError,
            content_type = "application/json"
        )
    )
)]
pub(crate) async fn booking_agent_instructions(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
) -> Result<Response, ApiError> {
    check_api_auth(&headers, &server)?;
    let page_ref = resolve_booking_page(&server, &page_token)?;
    let block = booking_agent_instructions_block(&server, &page_token, page_ref)?;
    if wants_html_fragment(&headers) {
        let fragment = render_booking_agent_instructions_block(&block)?;
        return Ok(([(CONTENT_TYPE, "text/html; charset=utf-8")], fragment).into_response());
    }
    let document = booking_agent_instructions_json(&block)?;
    Ok(([(CONTENT_TYPE, BOOKING_AGENT_INSTRUCTIONS_MIME)], document).into_response())
}

/// The page fragment and the document are two representations of one
/// resource. ONE-1815 asks for the fragment; a machine consumer asks for the
/// document; both carry the same bytes inside.
fn wants_html_fragment(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept.split(',').any(|entry| {
                entry
                    .split(';')
                    .next()
                    .is_some_and(|media| media.trim() == "text/html")
            })
        })
}

/// Ranked public slots for one booking page.
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/availability",
    params(
        ("page_token" = String, Path, description = "Opaque booking page token.")
    ),
    request_body(content = Object, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "Ranked public slots plus the flex-pool flag. Calendar titles, descriptions, attendees, and busy sources are not representable in this response.",
            body = Object,
            content_type = "application/json"
        ),
        (status = 400, description = "Malformed request or unusable constraint.", body = ApiError, content_type = "application/json"),
        (status = 401, description = "Missing or invalid bearer credentials.", body = ApiError, content_type = "application/json"),
        (status = 404, description = "No booking page resolves from this token.", body = ApiError, content_type = "application/json"),
        (status = 409, description = "Booking admission declined the request.", body = ApiError, content_type = "application/json")
    )
)]
pub(crate) async fn booking_availability(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    payload: Result<Json<BookingAvailabilityInput>, JsonRejection>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = http_transport_context(&headers, &server)?;
    let input = json_payload(payload)?;
    execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Availability(input),
        &transport,
    )
    .await
    .map(Json)
}

/// The typed two-stage `hold | confirm` flow.
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/book",
    params(
        ("page_token" = String, Path, description = "Opaque booking page token.")
    ),
    request_body(content = Object, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "Hold receipt with an opaque hold token and the server-capped expiry, a confirm receipt with distinct opaque reschedule and cancel tokens, or the nearest alternatives when the slot was taken.",
            body = Object,
            content_type = "application/json"
        ),
        (status = 400, description = "Malformed request or unusable constraint.", body = ApiError, content_type = "application/json"),
        (status = 401, description = "Missing or invalid bearer credentials.", body = ApiError, content_type = "application/json"),
        (status = 404, description = "No booking page resolves from this token.", body = ApiError, content_type = "application/json"),
        (status = 409, description = "Booking admission declined the request, or the lifecycle refused it.", body = ApiError, content_type = "application/json")
    )
)]
pub(crate) async fn booking_book(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    payload: Result<Json<BookingBookInput>, JsonRejection>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = http_transport_context(&headers, &server)?;
    let input = json_payload(payload)?;
    execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Book(input),
        &transport,
    )
    .await
    .map(Json)
}

/// Moves a booking, proving authority with its reschedule token.
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/reschedule",
    params(
        ("page_token" = String, Path, description = "Opaque booking page token.")
    ),
    request_body(content = Object, content_type = "application/json"),
    responses(
        (status = 200, description = "The booking moved; the reschedule token remains the action-scoped authority.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed request or malformed token.", body = ApiError, content_type = "application/json"),
        (status = 401, description = "Missing or invalid bearer credentials.", body = ApiError, content_type = "application/json"),
        (status = 404, description = "No booking page resolves from this token.", body = ApiError, content_type = "application/json"),
        (status = 409, description = "Booking admission declined the request, or the lifecycle refused it.", body = ApiError, content_type = "application/json")
    )
)]
pub(crate) async fn booking_reschedule(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    payload: Result<Json<BookingRescheduleInput>, JsonRejection>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = http_transport_context(&headers, &server)?;
    let input = json_payload(payload)?;
    execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Reschedule(input),
        &transport,
    )
    .await
    .map(Json)
}

/// Cancels a booking, proving authority with its cancel token.
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/cancel",
    params(
        ("page_token" = String, Path, description = "Opaque booking page token.")
    ),
    request_body(content = Object, content_type = "application/json"),
    responses(
        (status = 200, description = "The booking was cancelled.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed request or malformed token.", body = ApiError, content_type = "application/json"),
        (status = 401, description = "Missing or invalid bearer credentials.", body = ApiError, content_type = "application/json"),
        (status = 404, description = "No booking page resolves from this token.", body = ApiError, content_type = "application/json"),
        (status = 409, description = "Booking admission declined the request, or the lifecycle refused it.", body = ApiError, content_type = "application/json")
    )
)]
pub(crate) async fn booking_cancel(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    payload: Result<Json<BookingCancelInput>, JsonRejection>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = http_transport_context(&headers, &server)?;
    let input = json_payload(payload)?;
    execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Cancel(input),
        &transport,
    )
    .await
    .map(Json)
}

// -------------------------------------------------------------------------
// The shared executor
// -------------------------------------------------------------------------

/// The one door from a booking request to the merged booking capabilities.
///
/// The order is mandatory and is the contract of this function:
///
/// 1. validate the opaque page token, the operation shape, and the caller
///    keys, resolve the page subject internally, and bind any submitted action
///    token to that same page;
/// 2. call ONE-1817 admission exactly once, in the class this operation
///    belongs to;
/// 3. normalize free text through ONE-1816 and replace it with a canonical
///    `ConstraintObject`;
/// 4. call the merged oracle — for availability as the answer, for a hold as
///    the offerability gate a slot must pass before any verb is enqueued — and
///    let the home-node writer revalidate every mutation it executes;
/// 5. project only operation-safe response data.
///
/// A blocked request returns at step 2 and reaches neither the parser, the
/// oracle, nor the lifecycle.
///
/// # Errors
///
/// [`ApiError`] for a malformed request, an unresolvable page, a declined
/// admission, a refused lifecycle transition, or a storage failure.
pub(crate) async fn execute_booking_operation(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    transport: &BookingTransportContext,
) -> Result<BookingOperationResponse, ApiError> {
    // ── 1. shape, keys, and the page subject ────────────────────────────
    let page_ref = resolve_booking_page(server, page_token)?;
    validate_operation_shape(&request)?;
    check_action_token_page(&server.vault, page_ref, &request)?;
    let now = now_secs()?;

    // ── 2. the one admission call ───────────────────────────────────────
    let facts = admission_facts(server, page_ref, &request, transport, now)?;
    let disposition = match &request {
        BookingOperationRequest::Availability(_) => {
            enforce_slot_list(State(Arc::clone(server)), facts).await?
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(_)) => {
            enforce_hold(State(Arc::clone(server)), facts).await?
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(_))
        | BookingOperationRequest::Reschedule(_)
        | BookingOperationRequest::Cancel(_) => {
            enforce_book(State(Arc::clone(server)), facts).await?
        }
    };
    if let Some(response) = admission_short_circuit(&request, disposition)? {
        tracing::debug!(
            transport = transport.transport.as_str(),
            operation = request.operation().as_str(),
            "booking admission answered without solving or writing"
        );
        return Ok(response);
    }

    // ── 3, 4, 5. parse, dispatch, project ───────────────────────────────
    match request {
        BookingOperationRequest::Availability(input) => {
            let constraint = normalize_constraint(input.constraint, now)?;
            let solved = booking_oracle(server, page_ref, None, now)?.solve(&SolveRequest {
                event_type: input.event_type,
                window: input.window,
                constraint,
                visitor_tz: input.visitor_tz,
            })?;
            let SolveResult {
                slots, flex_used, ..
            } = solved;
            Ok(BookingOperationResponse::Availability { slots, flex_used })
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            execute_hold(server, page_ref, input, now).await
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            execute_confirm(server, page_ref, input, now).await
        }
        BookingOperationRequest::Reschedule(input) => {
            execute_reschedule(server, page_ref, input, now).await
        }
        BookingOperationRequest::Cancel(input) => {
            execute_cancel(server, page_ref, input, now).await
        }
    }
}

/// Binds a submitted action token to the page whose route carried it.
///
/// A reschedule or cancel token proves authority over ONE booking, and that
/// booking belongs to exactly one page. Nothing else in the request re-states
/// that: the URL page and the token are independent inputs, so without this
/// check a valid page-A token posted to page B's route would have the lifecycle
/// resolve page A's booking while admission, the minute windows, and the caps
/// were charged to page B — the page-mismatch invariant and the "admission
/// facts describe the page being acted on" property broken by one request.
///
/// The token's page comes from the lifecycle's own resolver, so this adds no
/// second decoder, no second key derivation, and no second opinion about what a
/// token means. It only reads: it writes nothing, enqueues nothing, and runs
/// before [`admission_facts`], so a mismatch spends no quota and reaches
/// neither the queue nor the writer.
///
/// A token this page cannot claim is refused exactly as an unknown token is, so
/// the answer is the same whether the credential was never minted or was minted
/// somewhere else: the refusal names no page, carries no identifier, and is no
/// oracle for "this token is real".
fn check_action_token_page(
    vault: &Vault,
    page_ref: EntityId,
    request: &BookingOperationRequest,
) -> Result<(), ApiError> {
    let token = match request {
        BookingOperationRequest::Reschedule(input) => &input.reschedule_token,
        BookingOperationRequest::Cancel(input) => &input.cancel_token,
        // Availability and hold name no booking at all, and confirm's authority
        // is a hold token the lifecycle already binds to this page's own
        // session key. Neither binding is widened or restated here.
        BookingOperationRequest::Availability(_) | BookingOperationRequest::Book(_) => {
            return Ok(());
        }
    };
    // A storage or codec failure propagates as the engine's own typed error
    // rather than as a verdict about the caller's token: either way nothing
    // proceeds, because there is no answer here that lets the request continue.
    let bound_page = token_page_ref(vault, &OpaqueLifecycleToken(token.clone()))?;
    if bound_page == Some(page_ref) {
        Ok(())
    } else {
        Err(unknown_action_token())
    }
}

/// The refusal an action token that names no booking on THIS page receives.
///
/// Deliberately the engine's own unknown-token sentence, projected through the
/// same [`booking_error`] envelope the lifecycle's refusal takes: a token minted
/// for another page must be indistinguishable from one that was never minted.
fn unknown_action_token() -> ApiError {
    // Byte-for-byte the sentence `lifecycle.rs` refuses an unresolvable token
    // with, so the two answers cannot drift apart into a distinguishable pair.
    const UNRESOLVED: &str = "token does not resolve to a booking";
    booking_error(BookingError::InvalidConstraint(UNRESOLVED.to_owned()))
}

/// Stage one: ask the oracle whether the slot is offerable at all, then
/// enqueue the lifecycle hold verb and drain it on the home node.
///
/// There is no caller TTL to honour. `checkout_lease_token`, when present, is
/// presented to [`HoldLeaseSpec::CheckoutExtension`], which the lifecycle only
/// accepts for a lease IT minted and still holds a live row for.
async fn execute_hold(
    server: &Arc<SyncServer>,
    page_ref: EntityId,
    mut input: BookingHoldInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let session_key = session_key(page_ref, &input.session_ref);
    // Taken rather than copied: the canonical object is the only constraint
    // with a reader after this line — the verb carries it, and the offerability
    // probe below asks the oracle with exactly the same bytes.
    let constraint = input
        .constraint
        .take()
        .map(ConstraintObject::canonicalize)
        .transpose()?;
    // Offerability decides BEFORE anything is minted. A slot this page never
    // offered gets the ordinary taken answer and no token at all.
    if let Some(unofferable) = unoffered_slot_answer(
        server,
        page_ref,
        &input,
        constraint.as_ref(),
        session_key,
        now,
    )? {
        return Ok(unofferable);
    }
    let lease = match input.checkout_lease_token {
        Some(token) => HoldLeaseSpec::CheckoutExtension {
            server_issued_lease: OpaqueCheckoutLeaseToken(token),
        },
        None => HoldLeaseSpec::Ordinary,
    };
    let receipt = run_booking_verb(
        server,
        BookingVerbRequest::Hold(HoldSpec {
            page_ref,
            event_type: input.event_type,
            slot: slot_range(input.selected_slot)?,
            session_key,
            visitor_tz: input.visitor_tz,
            constraint,
            lease,
            idempotency_key: Some(input.idempotency_key),
        }),
        Some(session_key),
        now,
    )
    .await?;
    match receipt {
        BookingVerbReceipt::Held(held) => {
            Ok(BookingOperationResponse::Book(BookingBookResult::Held {
                hold_token: held.token.0,
                selected_slot: SelectedSlot {
                    start_utc: held.slot.start,
                    end_utc: held.slot.end,
                },
                expires_at: held.expires_at,
            }))
        }
        BookingVerbReceipt::SlotTaken { alternatives } => Ok(BookingOperationResponse::Book(
            BookingBookResult::SlotTaken { alternatives },
        )),
        other => Err(unexpected_receipt("hold", &other)),
    }
}

/// Stage two: consume the opaque hold token on the home-node writer.
async fn execute_confirm(
    server: &Arc<SyncServer>,
    page_ref: EntityId,
    input: BookingConfirmInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let session_key = session_key(page_ref, &input.session_ref);
    let booker_contact = resolve_booker_contact(server, &input.booker_email, now)?;
    let receipt = run_booking_verb(
        server,
        BookingVerbRequest::Confirm(ConfirmSpec {
            hold_token: OpaqueLifecycleToken(input.hold_token),
            session_key,
            booker_contact,
            idempotency_key: Some(input.idempotency_key),
        }),
        Some(session_key),
        now,
    )
    .await?;
    match receipt {
        BookingVerbReceipt::Confirmed(confirmed) => Ok(BookingOperationResponse::Book(
            BookingBookResult::Confirmed {
                reschedule_token: confirmed.reschedule_token.0,
                cancel_token: confirmed.cancel_token.0,
            },
        )),
        BookingVerbReceipt::SlotTaken { alternatives } => Ok(BookingOperationResponse::Book(
            BookingBookResult::SlotTaken { alternatives },
        )),
        other => Err(unexpected_receipt("confirm", &other)),
    }
}

/// Moves a booking. Only the action-scoped token proves authority; a hold or
/// cancel token minted for a different action fails inside the lifecycle.
///
/// The resolved page is deliberately unused here: it was already compared
/// against this token's own page by [`check_action_token_page`], upstream of
/// admission, and the booking the lifecycle then loads is the token's. Keying
/// anything off the URL page at this depth would be a second, later, weaker
/// copy of that check.
async fn execute_reschedule(
    server: &Arc<SyncServer>,
    _page_ref: EntityId,
    input: BookingRescheduleInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let receipt = run_booking_verb(
        server,
        BookingVerbRequest::Reschedule(RescheduleSpec {
            token: OpaqueLifecycleToken(input.reschedule_token.clone()),
            new_slot: slot_range(input.selected_slot)?,
            visitor_tz: input.visitor_tz,
            constraint: None,
            idempotency_key: Some(input.idempotency_key),
        }),
        None,
        now,
    )
    .await?;
    match receipt {
        BookingVerbReceipt::Rescheduled(_) => Ok(BookingOperationResponse::Reschedule {
            reschedule_token: input.reschedule_token,
        }),
        BookingVerbReceipt::SlotTaken { .. } => {
            Err(ApiError::invalid_state(Some("booking_slot_taken")))
        }
        other => Err(unexpected_receipt("reschedule", &other)),
    }
}

/// Cancels a booking against its action-scoped cancel token.
///
/// The resolved page is unused for the same reason it is in
/// [`execute_reschedule`]: [`check_action_token_page`] already bound this token
/// to the page whose route carried it, before admission and before the queue.
async fn execute_cancel(
    server: &Arc<SyncServer>,
    _page_ref: EntityId,
    input: BookingCancelInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let receipt = run_booking_verb(
        server,
        BookingVerbRequest::Cancel(CancelSpec {
            token: OpaqueLifecycleToken(input.cancel_token.clone()),
            idempotency_key: Some(input.idempotency_key),
        }),
        None,
        now,
    )
    .await?;
    match receipt {
        BookingVerbReceipt::Cancelled(_) => Ok(BookingOperationResponse::Cancel {
            cancel_token: input.cancel_token,
        }),
        other => Err(unexpected_receipt("cancel", &other)),
    }
}

fn unexpected_receipt(verb: &str, receipt: &BookingVerbReceipt) -> ApiError {
    tracing::error!(
        verb = verb,
        receipt = ?std::mem::discriminant(receipt),
        "booking lifecycle answered a verb with another verb's receipt"
    );
    ApiError::internal_server_error("booking lifecycle returned an unexpected receipt")
}

// -------------------------------------------------------------------------
// Constraint normalization
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// MCP adapter
// -------------------------------------------------------------------------

/// Runs one MCP booking operation through the SAME executor the HTTP routes
/// use, and projects the shared response into the MCP result envelope.
///
/// The gateway performs no admission pre-check: it hands the request here and
/// the executor makes the one and only ONE-1817 call.
pub(crate) async fn execute_booking_operation_for_mcp(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    actor_ref: EntityId,
    source_ip: IpAddr,
) -> Result<BookingOperationResponse, ApiError> {
    let transport = BookingTransportContext {
        source_ip,
        authenticated_actor_ref: Some(actor_ref),
        transport: BookingTransport::Mcp,
    };
    execute_booking_operation(server, page_token, request, &transport).await
}
