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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};

use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_MIME, BOOKING_AGENT_INSTRUCTIONS_VERSION, BookingAgentEndpoint,
    BookingAgentInstructionsBlock, BookingAgentOperation, BookingAvailabilityInput,
    BookingBookInput, BookingBookResult, BookingCancelInput, BookingConfirmInput,
    BookingConstraintInput, BookingHoldInput, BookingIntakeAnswer, BookingOperationRequest,
    BookingOperationResponse, BookingRescheduleInput, SelectedSlot,
};
use oneiron::booking::anti_abuse::{
    BookingRequestFacts, EmailValidationEvidence, booking_email_hash, booking_ip_hash,
    booking_session_hash,
};
use oneiron::booking::config::{BOOKING_EVENT_TYPE_PREDICATE, decode_event_type_claim_value};
use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
use oneiron::booking::{
    ActiveHoldSource, BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_SOURCE_PAGE_PREDICATE,
    BOOKING_STATUS_PREDICATE, BookingBookerContactValue, BookingError,
    BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingOracleRequest, BookingSolver,
    BookingSourcePageValue, BookingStatus, BookingStatusValue, BookingVerbReceipt,
    BookingVerbRequest, CancelSpec, ConfirmSpec, ConstraintObject, EventTypeConfig, EventTypeKey,
    HoldLeaseSpec, HoldSpec, OpaqueCheckoutLeaseToken, OpaqueLifecycleToken, RescheduleSpec,
    SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource, enqueue_booking_verb,
    run_booking_lifecycle_once, token_page_ref,
};
use oneiron::dreamer_runner::DreamerHomeNodeClass;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarReadRequest, CalendarSel, ClaimLifecycleStatus, ClaimSubject, DreamerRunnerStore,
    EntityId, TimeRange, Vault,
};

use super::booking_anti_abuse::{
    BookingHttpDisposition, enforce_book, enforce_hold, enforce_slot_list,
};
use super::{check_api_auth, json_payload};
use crate::error::ApiError;
use crate::server::SyncServer;

// -------------------------------------------------------------------------
// Route shape
// -------------------------------------------------------------------------

/// Same-origin prefix every advertised booking path is relative to.
pub(crate) const BOOKING_ROUTE_PREFIX: &str = "/api/booking";

/// Lease owner recorded on the attempt row while this node drains one booking
/// verb. Named for the surface so a queue inspection says which door enqueued.
const BOOKING_LIFECYCLE_LEASE_OWNER: &str = "oneiron-server-booking-agent-api";

/// Domain tag for the page token digest. Domain separation is what stops a
/// page token from ever colliding with a lifecycle token digest computed over
/// the same bytes.
const PAGE_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.agent_api.page_token.v1\0";

/// Domain tag for the visitor session key material.
const SESSION_KEY_DOMAIN: &[u8] = b"oneiron.booking.agent_api.session.v1\0";

/// Domain tag for the canonical selected-slot hash carried in admission facts.
const SELECTED_SLOT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.selected_slot.v1\0";

/// Domain tag for the canonical intake hash carried in admission facts.
const INTAKE_DOMAIN: &[u8] = b"oneiron.booking.agent_api.intake.v1\0";

/// Domain tag for the deterministic booker-contact subject derived from a
/// confirmed email address.
const BOOKER_CONTACT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.booker_contact.v1\0";

/// A page token is the lowercase hex of this many digest bytes.
const PAGE_TOKEN_BYTES: usize = 16;

/// Prefix every page token carries.
///
/// Load-bearing, not decoration: without it a 32-character hex token would be
/// SHAPED like an entity id, and a reviewer — or a future handler — could
/// mistake one for the other. With it, a page token cannot be parsed as an
/// `EntityId` and an `EntityId` cannot be presented as a page token.
const PAGE_TOKEN_PREFIX: &str = "bkp_";

/// Bound on the opaque per-session reference a caller may supply. It matches
/// the bound ONE-1816's front applies to the same field, so a reference this
/// surface admits is one the constraint front could also carry.
const MAX_SESSION_REF_BYTES: usize = 120;

/// Bound on the booker email a confirm may carry.
const MAX_BOOKER_EMAIL_BYTES: usize = 254;

/// Bound on one intake answer's field key.
const MAX_INTAKE_FIELD_KEY_BYTES: usize = 64;

/// Bound on one intake answer's value.
const MAX_INTAKE_VALUE_BYTES: usize = 4096;

/// Bound on how many intake answers one confirm may carry.
const MAX_INTAKE_ANSWERS: usize = 32;

/// Bound on a caller-supplied idempotency key. The lifecycle applies its own
/// bound too; this one fails the request before a verb is ever built.
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

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
// Instructions document + embeddable fragment
// -------------------------------------------------------------------------

/// Builds the canonical instructions block for one resolved page.
///
/// Operations are emitted in [`BookingAgentOperation::CANONICAL`] order and
/// every path is relative and same-origin, so two nodes serving the same page
/// produce the same bytes.
pub(crate) fn booking_agent_instructions_block(
    server: &SyncServer,
    page_token: &str,
    page_ref: EntityId,
) -> Result<BookingAgentInstructionsBlock, ApiError> {
    // Configuration claims have no inherent order, so the block imposes one:
    // the same page must produce the same bytes on every node.
    let mut keys: Vec<String> = page_event_type_configs(&server.vault, page_ref)?
        .into_iter()
        .map(|config| config.key.0)
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let event_types: Vec<EventTypeKey> = keys.into_iter().map(EventTypeKey).collect();

    // Every operation is a POST: each one carries a typed body, and none of
    // them is safe to cache or replay from a URL alone.
    let operations = BookingAgentOperation::CANONICAL
        .into_iter()
        .map(|operation| BookingAgentEndpoint {
            operation,
            method: "POST".to_owned(),
            path: format!("{BOOKING_ROUTE_PREFIX}/{page_token}/{}", operation.as_str()),
        })
        .collect();

    let block = BookingAgentInstructionsBlock {
        version: BOOKING_AGENT_INSTRUCTIONS_VERSION,
        page_token: page_token.to_owned(),
        event_types,
        operations,
        constraint_schema_version: CONSTRAINT_SCHEMA_VERSION,
    };
    block.validate().map_err(|defect| {
        tracing::error!(
            defect = defect.as_str(),
            "booking agent instructions defect"
        );
        ApiError::internal_server_error("booking agent instructions block is not canonical")
    })?;
    Ok(block)
}

/// The canonical JSON bytes of one instructions block.
///
/// This is the single serializer: the HTTP document and the embedded fragment
/// both come from here, so byte-equivalence is a property of the code rather
/// than of two implementations agreeing.
pub(crate) fn booking_agent_instructions_json(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    serde_json::to_string(block)
        .map_err(|_| ApiError::internal_server_error("booking agent instructions do not serialize"))
}

/// Renders the embeddable, script-safe `<script type=...>` fragment.
///
/// ONE-1815 inserts this into its rendered page verbatim. It may style around
/// the fragment; it cannot mutate the versioned JSON contract inside it.
///
/// Script safety is structural. The JSON is escaped so that no `<`, `>`, or
/// `&` survives into the document, which makes `</script>` unrepresentable
/// inside the block, and U+2028/U+2029 are escaped so the block stays a single
/// JavaScript source line. Every escape is a legal JSON string escape, so the
/// decoded value is byte-identical to
/// [`booking_agent_instructions_json`] after re-serialization.
pub(crate) fn render_booking_agent_instructions_block(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    let json = booking_agent_instructions_json(block)?;
    Ok(format!(
        "<script type=\"{BOOKING_AGENT_INSTRUCTIONS_MIME}\">{}</script>",
        script_safe_json(&json)
    ))
}

/// Escapes the four characters that could terminate or reshape the block.
fn script_safe_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for character in json.chars() {
        match character {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
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

/// Builds the transport context for one HTTP request.
///
/// The bearer check is the existing `check_api_auth` door. The actor
/// reference, when the credential carries one, is read from the authenticated
/// principal — never from the request body.
fn http_transport_context(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<BookingTransportContext, ApiError> {
    check_api_auth(headers, server)?;
    Ok(BookingTransportContext {
        source_ip: request_source_ip(headers),
        authenticated_actor_ref: None,
        transport: BookingTransport::PublicHttp,
    })
}

/// The caller address admission keys on.
///
/// The app is served without connection-info state, so the forwarding header
/// a reverse proxy sets is the connection evidence available. With no header
/// the request came over the loopback listener and is keyed as such — never as
/// an absent or wildcard address, which would merge every caller into one
/// bucket.
fn request_source_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
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
            let SolveResult { slots, flex_used } = solved;
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

/// The oracle's verdict on the slot a hold names, taken before a token exists.
///
/// The hold verb records a soft hold; the re-solve that decides a CONTESTED
/// slot lives in confirm and reschedule, and stays there — a slot that was
/// offered and then went to someone else is the writer's call, not this one's.
/// But a slot the page never offered at all must not reach a lifecycle
/// credential: an invented interval would otherwise come back carrying a real
/// hold token, and the caller would learn one stage later that it was never
/// bookable.
///
/// So this asks the SAME oracle availability answers from, over exactly the
/// interval the caller selected, with this session's own live hold hidden — the
/// same exclusion the lifecycle applies — so a caller re-holding its own slot
/// is never refused by itself. Equality, not containment: the oracle's UTC
/// bounds are authoritative and nothing here rounds or widens them, and the
/// window is the caller's own slot, so this adds no window policy, no cap, and
/// no threshold of its own. It reads; it never writes and never decides what is
/// writable.
fn unoffered_slot_answer(
    server: &SyncServer,
    page_ref: EntityId,
    input: &BookingHoldInput,
    constraint: Option<&ConstraintObject>,
    session_key: SessionKey,
    now: u64,
) -> Result<Option<BookingOperationResponse>, ApiError> {
    let slot = slot_range(input.selected_slot)?;
    let solved =
        booking_oracle(server, page_ref, Some(session_key), now)?.solve(&SolveRequest {
            event_type: input.event_type.clone(),
            window: offerability_window(slot),
            constraint: constraint.cloned(),
            visitor_tz: input.visitor_tz.clone(),
        })?;
    if solved
        .slots
        .iter()
        .any(|ranked| ranked.start_utc == slot.start && ranked.end_utc == slot.end)
    {
        return Ok(None);
    }
    // The same shape a taken slot returns from the writer, and for the same
    // reason: nothing was written, so this is a result rather than an error.
    // The alternatives are exactly what this solve saw inside the caller's own
    // interval; nothing here widens the window to look for more, because the
    // operation that answers "when else?" is availability, and there the caller
    // chooses the window itself.
    let taken = BookingBookResult::SlotTaken {
        alternatives: solved.slots,
    };
    Ok(Some(BookingOperationResponse::Book(taken)))
}

/// The inclusive solve window for one half-open slot.
///
/// [`SolveRequest::window`] is inclusive of its end instant, so the window that
/// means "exactly this slot" ends at the slot's last second. The caller's slot
/// has already passed [`slot_range`], so `end` is at least `start + 1`.
const fn offerability_window(slot: TimeRange) -> TimeRange {
    TimeRange {
        start: slot.start,
        end: slot.end.saturating_sub(1),
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
// Lifecycle drive
// -------------------------------------------------------------------------

/// Enqueues one verb and drains exactly one home-node consumer turn.
///
/// The verb door and the writer door are the merged lifecycle's, not a second
/// implementation: this function only enqueues, builds the per-attempt oracle,
/// and reports the receipt. Correctness — slot revalidation, mutual exclusion,
/// receipt identity — belongs to the writer.
async fn run_booking_verb(
    server: &Arc<SyncServer>,
    request: BookingVerbRequest,
    exclude_session: Option<SessionKey>,
    now: u64,
) -> Result<BookingVerbReceipt, ApiError> {
    let vault: &Vault = &server.vault;
    let local_node_id = local_booking_node_id(server)?;
    enqueue_booking_verb(vault, request, now)?;
    let turn = run_booking_lifecycle_once(
        vault,
        |oracle_request: &BookingOracleRequest| {
            let page_ref = oracle_request.page_ref.ok_or_else(|| {
                BookingError::SlotOracle(
                    "booking attempt names no page in committed state".to_owned(),
                )
            })?;
            Ok(ServerBookingOracle {
                vault,
                page_ref,
                exclude_session_key: oracle_request.exclude_session_key.or(exclude_session),
                now_utc: now,
                calendars: page_calendar_bindings(vault, page_ref)?,
            })
        },
        &BookingLifecycleConsumerInput {
            local_node_id,
            lease_owner: BOOKING_LIFECYCLE_LEASE_OWNER.to_owned(),
            now_utc: now,
        },
    )?;
    match turn {
        BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
        BookingLifecycleTurn::NoHomeNode => {
            Err(ApiError::invalid_state(Some("booking_no_home_node_writer")))
        }
        BookingLifecycleTurn::NotHomeNode { .. } => Err(ApiError::invalid_state(Some(
            "booking_writer_is_another_node",
        ))),
        // The attempt this call enqueued was drained by another worker before
        // this turn claimed it. The write may still land; the caller retries
        // with the same idempotency key and coalesces onto the same attempt.
        BookingLifecycleTurn::Empty => Err(ApiError::invalid_state(Some(
            "booking_attempt_claimed_elsewhere",
        ))),
        other => {
            tracing::error!(turn = ?other, "booking lifecycle returned an unknown turn");
            Err(ApiError::internal_server_error(
                "booking lifecycle returned an unknown turn",
            ))
        }
    }
}

/// This daemon's node id for the booking home-node check.
///
/// A hosted deployment gives each tenant daemon a nonzero `lease_vault_id`,
/// which IS its node identity. A single-vault local deployment leaves it at
/// zero, and there the operator's own always-on-local designation names this
/// device — the one class that means "the machine holding this vault". A
/// cloud-attached or primary-device designation names some OTHER node, so
/// this daemon reports no id and the lifecycle refuses to write, which is the
/// correct fail-closed answer rather than a claim of authority.
fn local_booking_node_id(server: &SyncServer) -> Result<u64, ApiError> {
    if server.config.lease_vault_id != 0 {
        return Ok(server.config.lease_vault_id);
    }
    let designation = DreamerRunnerStore::new(&server.vault)
        .home_node_designation()
        .map_err(engine_read_error)?;
    designation
        .filter(|designation| designation.class == DreamerHomeNodeClass::AlwaysOnLocal)
        .map(|designation| designation.node_id)
        .ok_or_else(|| ApiError::invalid_state(Some("booking_no_home_node_writer")))
}

/// The merged production oracle, bound to this page and to committed holds.
///
/// It implements [`SlotOracle`] rather than reimplementing one: availability
/// and every lifecycle revalidation see the same solver, the same
/// configuration claim, and the same live-hold view.
struct ServerBookingOracle<'a> {
    vault: &'a Vault,
    page_ref: EntityId,
    exclude_session_key: Option<SessionKey>,
    now_utc: u64,
    calendars: Vec<(EntityId, Vec<CalendarSel>)>,
}

impl SlotOracle for ServerBookingOracle<'_> {
    fn solve(&self, request: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude_session_key {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        BookingSolver {
            vault: self.vault,
            page_ref: self.page_ref,
            calendars_by_host: &self.calendars,
            holds: &holds,
            now_utc: self.now_utc,
            // `None` means "resolve the live `booking.event_type` claim on
            // this page". The synthetic arm belongs to page-less companion
            // presets, and a booking page is never page-less.
            synthetic_config: None,
        }
        .solve(request)
    }
}

/// Builds the oracle for one page outside the lifecycle, for availability.
fn booking_oracle<'a>(
    server: &'a SyncServer,
    page_ref: EntityId,
    exclude_session_key: Option<SessionKey>,
    now: u64,
) -> Result<ServerBookingOracle<'a>, ApiError> {
    Ok(ServerBookingOracle {
        vault: &server.vault,
        page_ref,
        exclude_session_key,
        now_utc: now,
        calendars: page_calendar_bindings(&server.vault, page_ref)?,
    })
}

/// The request-time host to calendar binding the solver asks CAL through.
///
/// One entry per configured host, so a host's availability is never
/// contaminated by another host's feed. The selector stays unfiltered because
/// the passport-index selector is CAL-02's and is ignored on this baseline; a
/// host with no configured calendar is a configuration defect the solver
/// refuses, not a free host.
fn page_calendar_bindings(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<(EntityId, Vec<CalendarSel>)>, BookingError> {
    let mut bindings: Vec<(EntityId, Vec<CalendarSel>)> = Vec::new();
    for config in page_event_type_configs_engine(vault, page_ref)? {
        for host in &config.hosts {
            if bindings.iter().any(|(id, _)| *id == host.host_ref) {
                continue;
            }
            bindings.push((host.host_ref, vec![CalendarSel { system: None }]));
        }
    }
    Ok(bindings)
}

// -------------------------------------------------------------------------
// Admission
// -------------------------------------------------------------------------

/// Builds the ONE-1817 facts for one request.
///
/// The identity inputs — source address, booker email, visitor session, and
/// the authenticated actor — are derived the same way for both transports, so
/// a caller cannot get a fresh budget by switching doors.
fn admission_facts(
    server: &SyncServer,
    page_ref: EntityId,
    request: &BookingOperationRequest,
    transport: &BookingTransportContext,
    now: u64,
) -> Result<BookingRequestFacts, ApiError> {
    let mut ip_material = transport.source_ip.to_string();
    if let Some(actor) = transport.actor_key() {
        // An authenticated connector actor keys its own bucket, so two agents
        // behind one address keep independent budgets — the same reason the
        // engine keys the book window on the IP+email pair.
        ip_material.push('\0');
        ip_material.push_str(&actor);
    }
    let ip_hash = booking_ip_hash(&ip_material);

    let (event_type, session_ref, booker_email, selected_slot, intake) = match request {
        BookingOperationRequest::Availability(input) => (
            Some(input.event_type.clone()),
            Some(input.session_ref.as_str()),
            None,
            None,
            None,
        ),
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => (
            Some(input.event_type.clone()),
            Some(input.session_ref.as_str()),
            None,
            Some(input.selected_slot),
            None,
        ),
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => (
            None,
            Some(input.session_ref.as_str()),
            Some(input.booker_email.as_str()),
            None,
            Some(input.intake.as_slice()),
        ),
        BookingOperationRequest::Reschedule(input) => {
            (None, None, None, Some(input.selected_slot), None)
        }
        BookingOperationRequest::Cancel(_) => (None, None, None, None, None),
    };

    let session_hash = session_ref.map(booking_session_hash);
    let email_hash = booker_email.map(booking_email_hash);
    let live_session_holds = match session_ref {
        Some(reference) => {
            active_holds_for_session(server, page_ref, &session_key(page_ref, reference), now)?
        }
        None => 0,
    };
    let live_email_bookings = match booker_email {
        Some(email) => active_future_bookings_for_email(server, page_ref, email, now)?,
        None => 0,
    };
    let intake_chars: usize = intake.map_or(0, |answers| {
        answers
            .iter()
            .map(|answer| answer.value.chars().count())
            .sum()
    });

    Ok(BookingRequestFacts {
        page_ref,
        event_type,
        ip_hash,
        email_hash,
        session_hash,
        // The honeypot field and the time-to-submit floor are evidence about
        // an HTML form fill. This surface has neither: it carries no honeypot
        // input and no form session, so both signals are asserted as absent
        // rather than fabricated. Every control that does have evidence here —
        // the minute windows, the hold cap, the email checks, and the
        // active-booking cap — is fed real values above and below.
        started_at_millis: 0,
        submitted_at_millis: now.saturating_mul(1_000),
        // Overwritten by the book guard at its trusted admission boundary.
        submission_fingerprint: [0_u8; 32],
        selected_slot_hash: selected_slot_hash(selected_slot),
        intake_content_hash: intake_content_hash(intake),
        honeypot_nonempty: false,
        intake_chars,
        active_future_bookings_for_email: live_email_bookings,
        active_holds_for_session: live_session_holds,
        email: booker_email.map(|email| EmailValidationEvidence {
            syntax_valid: is_syntactically_valid_email(email),
            // MX resolution and disposable-domain lists are network lookups
            // this surface does not perform. `None` and `false` are the
            // engine's "no signal" readings, never a negative one.
            mx_present: None,
            disposable_domain: false,
        }),
    })
}

/// Projects a non-`Continue` admission disposition onto an answer.
///
/// `Continue` returns `None` and the executor proceeds. Every other
/// disposition returns here, so a declined request reaches neither the parser,
/// the oracle, nor the lifecycle.
fn admission_short_circuit(
    request: &BookingOperationRequest,
    disposition: BookingHttpDisposition,
) -> Result<Option<BookingOperationResponse>, ApiError> {
    match disposition {
        BookingHttpDisposition::Continue => Ok(None),
        // Silent reject and quarantine-and-accept both answer exactly like an
        // ordinary success and write no booking. The benign shape per
        // operation is the empty one: no slots, no lifecycle receipt, and the
        // caller's own action token echoed back.
        BookingHttpDisposition::SilentOk | BookingHttpDisposition::QuarantineAndAccept => {
            Ok(Some(benign_response(request)))
        }
        BookingHttpDisposition::PromptCorrection { body } => Err(prompt_correction_error(&body)),
        BookingHttpDisposition::RetryAfter { seconds } => {
            let state = format!("booking_retry_after_{seconds}s");
            Err(ApiError::new(
                format!("booking admission is rate limited; retry after {seconds} seconds"),
                crate::error::ApiErrorDetails::InvalidState { state: Some(state) },
                [format!(
                    "Wait {seconds} seconds before retrying this booking request."
                )],
            ))
        }
    }
}

/// The success-shaped answer a silent rejection returns.
fn benign_response(request: &BookingOperationRequest) -> BookingOperationResponse {
    match request {
        BookingOperationRequest::Availability(_) => BookingOperationResponse::Availability {
            slots: Vec::new(),
            flex_used: false,
        },
        BookingOperationRequest::Book(_) => {
            BookingOperationResponse::Book(BookingBookResult::SlotTaken {
                alternatives: Vec::new(),
            })
        }
        BookingOperationRequest::Reschedule(input) => BookingOperationResponse::Reschedule {
            reschedule_token: input.reschedule_token.clone(),
        },
        BookingOperationRequest::Cancel(input) => BookingOperationResponse::Cancel {
            cancel_token: input.cancel_token.clone(),
        },
    }
}

/// Re-projects the engine's correction body onto the typed API error.
///
/// The engine owns the field and the sentence; this only chooses the envelope.
fn prompt_correction_error(body: &str) -> ApiError {
    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();
    let field = parsed
        .as_ref()
        .and_then(|value| value.get("field"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("this booking request needs a correction before it can proceed")
        .to_owned();
    ApiError::bad_request(message, field.as_deref())
}

/// How many live holds this session already holds on this page.
///
/// Derived from the merged hold source rather than a second hold store: the
/// difference between the unfiltered view and the view that hides this session
/// IS this session's live hold count.
fn active_holds_for_session(
    server: &SyncServer,
    page_ref: EntityId,
    session_key: &SessionKey,
    now: u64,
) -> Result<u8, ApiError> {
    let window = TimeRange {
        start: now,
        end: u64::MAX,
    };
    let all = VaultActiveHoldSource::new(&server.vault)
        .active_holds(page_ref, window, now, None)?
        .len();
    let others = VaultActiveHoldSource::excluding(&server.vault, *session_key)
        .active_holds(page_ref, window, now, None)?
        .len();
    Ok(u8::try_from(all.saturating_sub(others)).unwrap_or(u8::MAX))
}

/// How many active future bookings this email already holds on this page.
///
/// Read from the committed booking claims the lifecycle writes, so the cap
/// counts the same bookings a cancellation would remove.
fn active_future_bookings_for_email(
    server: &SyncServer,
    page_ref: EntityId,
    email: &str,
    now: u64,
) -> Result<u8, ApiError> {
    let contact_ref = booker_contact_ref(email)?;
    let vault = &server.vault;
    let mut count: u8 = 0;
    let mut after: Option<EntityId> = None;
    loop {
        let page = vault
            .entities_by_type_page(ENTITY_TYPE_EVENT, after.as_ref(), 512)
            .map_err(engine_read_error)?;
        if page.is_empty() {
            break;
        }
        after = page.last().copied();
        for event_ref in page {
            if booking_is_active_future_for(vault, event_ref, page_ref, contact_ref, now)? {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

/// Whether one EVENT is this page's active, still-upcoming booking for one
/// contact. Every axis is read from the lifecycle's own claim family; the
/// occurrence comes from the calendar surface's own read-only projection
/// rather than a second header decoder.
fn booking_is_active_future_for(
    vault: &Vault,
    event_ref: EntityId,
    page_ref: EntityId,
    contact_ref: EntityId,
    now: u64,
) -> Result<bool, ApiError> {
    let claim_ids = vault
        .claims_for_subject(&event_ref)
        .map_err(engine_read_error)?;
    let (mut same_page, mut same_contact, mut confirmed) = (false, false, false);
    for claim_id in claim_ids {
        let Some(body) = vault.get_claim(&claim_id).map_err(engine_read_error)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                same_page = decode_claim_value::<BookingSourcePageValue>(&body.value)
                    .is_some_and(|value| value.page_ref == page_ref);
            }
            BOOKING_BOOKER_CONTACT_PREDICATE => {
                same_contact = decode_claim_value::<BookingBookerContactValue>(&body.value)
                    .is_some_and(|value| value.contact_ref == contact_ref);
            }
            BOOKING_STATUS_PREDICATE => {
                confirmed = decode_claim_value::<BookingStatusValue>(&body.value)
                    .is_some_and(|value| value.status == BookingStatus::Confirmed);
            }
            _ => {}
        }
    }
    if !(same_page && same_contact && confirmed) {
        return Ok(false);
    }
    // Still upcoming: a booking already in the past holds no future slot and
    // must not consume the cap. Over-counting here would BLOCK a visitor the
    // engine's under-block posture says to admit.
    let occurrence = oneiron::calendar::query::read_event(
        vault,
        &CalendarReadRequest {
            event_ref: event_ref.to_hex(),
        },
    )
    .map_err(engine_read_error)?;
    Ok(occurrence.is_none_or(|view| view.end_utc.is_none_or(|end| end > now)))
}

/// Decodes one opaque MessagePack claim value into a typed booking value.
fn decode_claim_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

fn selected_slot_hash(slot: Option<SelectedSlot>) -> [u8; 32] {
    // One presence byte plus two big-endian u64s.
    let mut material = Vec::with_capacity(17);
    match slot {
        Some(slot) => {
            material.push(1);
            material.extend_from_slice(&slot.start_utc.to_be_bytes());
            material.extend_from_slice(&slot.end_utc.to_be_bytes());
        }
        None => material.push(0),
    }
    domain_digest(SELECTED_SLOT_DOMAIN, &material)
}

fn intake_content_hash(intake: Option<&[BookingIntakeAnswer]>) -> [u8; 32] {
    let mut material = Vec::new();
    match intake {
        Some(answers) => {
            material.push(1);
            material.extend_from_slice(&(answers.len() as u64).to_be_bytes());
            for answer in answers {
                material.extend_from_slice(&(answer.field_key.len() as u64).to_be_bytes());
                material.extend_from_slice(answer.field_key.as_bytes());
                material.extend_from_slice(&(answer.value.len() as u64).to_be_bytes());
                material.extend_from_slice(answer.value.as_bytes());
            }
        }
        None => material.push(0),
    }
    domain_digest(INTAKE_DOMAIN, &material)
}

/// A deliberately structural check: an address shaped like an address. Deeper
/// evidence is the engine's `EmailValidationEvidence`, and this surface
/// supplies only what it can actually observe.
fn is_syntactically_valid_email(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !email.contains(char::is_whitespace)
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
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
// Shape validation
// -------------------------------------------------------------------------

/// Validates the caller-controlled shape of one request before any storage
/// read, any admission call, and any solve.
fn validate_operation_shape(request: &BookingOperationRequest) -> Result<(), ApiError> {
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

fn validate_selected_slot(slot: SelectedSlot) -> Result<(), ApiError> {
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

// -------------------------------------------------------------------------
// Opaque page tokens
// -------------------------------------------------------------------------

/// The opaque public token for one booking page.
///
/// A domain-separated digest, truncated to [`PAGE_TOKEN_BYTES`]. It is a
/// ONE-WAY function of the page subject: the token carries no identifier and
/// no caller can run it backwards, which is what lets the executor accept it
/// from public data without ever accepting an `EntityId`.
#[must_use]
pub(crate) fn booking_page_token(page_ref: EntityId) -> String {
    let digest = domain_digest(PAGE_TOKEN_DOMAIN, page_ref.as_bytes());
    format!(
        "{PAGE_TOKEN_PREFIX}{}",
        hex_lower(&digest[..PAGE_TOKEN_BYTES])
    )
}

/// Resolves an opaque page token to the booking page it names.
///
/// The memo is a node-local shortcut over a deterministic derivation, so a
/// miss means "look again", never "absent": the authoritative answer is always
/// the scan, and the scan only ever names pages the vault already carries a
/// live `booking.event_type` claim for.
pub(crate) fn resolve_booking_page(
    server: &SyncServer,
    page_token: &str,
) -> Result<EntityId, ApiError> {
    validate_page_token_shape(page_token)?;
    if let Some(page_ref) = memoized_page(page_token)
        && page_is_bookable(&server.vault, page_ref)?
    {
        return Ok(page_ref);
    }
    for page_ref in booking_page_candidates(&server.vault)? {
        if booking_page_token(page_ref) == page_token {
            memoize_page(page_token, page_ref);
            return Ok(page_ref);
        }
    }
    Err(ApiError::not_found("booking page", Some(page_token)))
}

fn validate_page_token_shape(page_token: &str) -> Result<(), ApiError> {
    let well_formed = page_token
        .strip_prefix(PAGE_TOKEN_PREFIX)
        .is_some_and(|digest| {
            digest.len() == PAGE_TOKEN_BYTES * 2
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if well_formed {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            format!(
                "page_token must be {PAGE_TOKEN_PREFIX} followed by 32 lowercase hex characters"
            ),
            Some("page_token"),
        ))
    }
}

fn page_token_memo() -> &'static Mutex<HashMap<String, EntityId>> {
    static MEMO: OnceLock<Mutex<HashMap<String, EntityId>>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

fn memoized_page(page_token: &str) -> Option<EntityId> {
    page_token_memo()
        .lock()
        .ok()
        .and_then(|memo| memo.get(page_token).copied())
}

fn memoize_page(page_token: &str, page_ref: EntityId) {
    if let Ok(mut memo) = page_token_memo().lock() {
        memo.insert(page_token.to_owned(), page_ref);
    }
}

/// Whether a page still carries a booking configuration claim.
fn page_is_bookable(vault: &Vault, page_ref: EntityId) -> Result<bool, ApiError> {
    Ok(!page_event_type_configs(vault, page_ref)?.is_empty())
}

/// Every entity carrying a live `booking.event_type` claim.
///
/// The claim family is the definition of a booking page: nothing else makes
/// an entity bookable, so nothing else can answer a page token.
fn booking_page_candidates(vault: &Vault) -> Result<Vec<EntityId>, ApiError> {
    let mut pages: Vec<EntityId> = Vec::new();
    let mut after: Option<EntityId> = None;
    loop {
        let page = vault
            .entities_by_type_page(ENTITY_TYPE_CLAIM, after.as_ref(), 512)
            .map_err(engine_read_error)?;
        if page.is_empty() {
            break;
        }
        after = page.last().copied();
        for claim_id in page {
            let Some(body) = vault.get_claim(&claim_id).map_err(engine_read_error)? else {
                continue;
            };
            if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            if let ClaimSubject::Entity(subject) = body.subject
                && !pages.contains(&subject)
            {
                pages.push(subject);
            }
        }
    }
    Ok(pages)
}

/// Every event-type configuration live on one booking page.
fn page_event_type_configs(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<EventTypeConfig>, ApiError> {
    page_event_type_configs_engine(vault, page_ref).map_err(booking_error)
}

fn page_event_type_configs_engine(
    vault: &Vault,
    page_ref: EntityId,
) -> Result<Vec<EventTypeConfig>, BookingError> {
    let claim_ids = vault
        .claims_for_subject(&page_ref)
        .map_err(|_| BookingError::SlotOracle("booking page claim read failed".to_owned()))?;
    let mut configs = Vec::new();
    for claim_id in claim_ids {
        let Ok(Some(body)) = vault.get_claim(&claim_id) else {
            continue;
        };
        if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.subject != ClaimSubject::Entity(page_ref)
        {
            continue;
        }
        // Past this point the row IS a booking configuration claim, so a
        // malformed body is a typed failure rather than a silent skip.
        let decoded = decode_event_type_claim_value(&body.value)?;
        if decoded.page_ref == page_ref {
            configs.push(decoded.config);
        }
    }
    Ok(configs)
}

// -------------------------------------------------------------------------
// Subject resolution
// -------------------------------------------------------------------------

/// The visitor session key holds are keyed by.
///
/// Bound to the page as well as to the caller's reference, so one session
/// reference cannot carry a hold across pages.
fn session_key(page_ref: EntityId, session_ref: &str) -> SessionKey {
    let mut material = Vec::with_capacity(16 + 1 + session_ref.len());
    material.extend_from_slice(page_ref.as_bytes());
    material.push(0);
    material.extend_from_slice(session_ref.as_bytes());
    SessionKey::derive(&domain_digest(SESSION_KEY_DOMAIN, &material))
}

/// The deterministic contact subject one booker email resolves to.
///
/// Deterministic so a retry converges on the same subject instead of minting
/// a second contact for the same person, and derived server-side so a caller
/// can never name the subject a booking is attributed to.
fn booker_contact_ref(email: &str) -> Result<EntityId, ApiError> {
    let normalized = email.trim().to_lowercase();
    let digest = domain_digest(BOOKER_CONTACT_DOMAIN, normalized.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    EntityId::from_bytes(bytes)
        .map_err(|_| ApiError::internal_server_error("booker contact subject is not addressable"))
}

/// Resolves the contact subject, materializing it the first time this address
/// books. The subject carries the address itself and nothing else.
fn resolve_booker_contact(
    server: &SyncServer,
    email: &str,
    now: u64,
) -> Result<EntityId, ApiError> {
    let contact_ref = booker_contact_ref(email)?;
    let existing = server
        .vault
        .get_entity_type(&contact_ref)
        .map_err(engine_read_error)?;
    if existing.is_none() {
        server
            .vault
            .put_entity(
                &contact_ref,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                email.trim().to_lowercase().as_bytes(),
            )
            .map_err(engine_read_error)?;
    }
    Ok(contact_ref)
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

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

fn slot_range(slot: SelectedSlot) -> Result<TimeRange, ApiError> {
    validate_selected_slot(slot)?;
    Ok(TimeRange {
        start: slot.start_utc,
        end: slot.end_utc,
    })
}

fn domain_digest(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
}

fn now_secs() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal_server_error("booking clock unavailable"))
}

fn engine_read_error(error: oneiron::Error) -> ApiError {
    tracing::error!(error = %error, "booking agent api vault read failed");
    ApiError::internal_server_error("booking storage read failed")
}

/// Projects a typed engine booking error onto the API vocabulary.
///
/// Configuration and storage defects are the server's; constraint, parse, and
/// oracle refusals are the caller's request being unusable, and a spent
/// session dial is a retry-class state.
fn booking_error(error: BookingError) -> ApiError {
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
    }
}

impl From<BookingError> for ApiError {
    fn from(error: BookingError) -> Self {
        booking_error(error)
    }
}
