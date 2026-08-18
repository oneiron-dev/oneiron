//! ONE-1819 [BK-08] agent-readable booking page + direct-book API/MCP.
//!
//! One shared executor powers the public HTTP routes and the `oneiron.book`
//! MCP tool, so validation, BK-06 admission, free-text normalization,
//! solver/lifecycle dispatch, and response projection cannot drift between
//! transports.
//!
//! Boundaries this file keeps:
//!
//! * Every Axum handler threads `State<Arc<SyncServer>>` and returns
//!   [`ApiError`]. No `ApiState`, `AppState`, `VaultFacade`, or
//!   `WritePrincipal` is introduced.
//! * The ONE-1817 anti-abuse admission API is called EXACTLY ONCE per request,
//!   inside [`execute_booking_operation`], before any parse, solve, or
//!   lifecycle work. Neither the HTTP handlers nor the MCP gateway pre-check
//!   it, and no threshold is copied here.
//! * Public data addresses pages and bookings only by opaque `String` tokens.
//!   The page token resolves through the engine's existing presentation-id
//!   door; a caller that presents a raw 32-hex entity id is refused.
//! * Availability answers with ONE-1812's already-clamped public projection:
//!   ranked UTC slots and the flex flag. No calendar title, attendee, or busy
//!   interval has a field to travel in.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};

use oneiron::booking::agent_api::{
    BOOKING_AGENT_INSTRUCTIONS_MIME, BOOKING_AGENT_INSTRUCTIONS_VERSION, BookingAgentEndpoint,
    BookingAgentInstructionsBlock, BookingAgentOperation, BookingAvailabilityInput,
    BookingBookInput, BookingBookResult, BookingCancelInput, BookingConfirmInput,
    BookingConstraintInput, BookingHoldInput, BookingOperationRequest, BookingOperationResponse,
    BookingRescheduleInput, SelectedSlot,
};
use oneiron::booking::anti_abuse::{BookingRequestFacts, EmailValidationEvidence};

use super::booking_anti_abuse::{
    BookingHttpDisposition, enforce_book, enforce_hold, enforce_slot_list,
};
use crate::error::ApiError;
use crate::server::SyncServer;

/// Route prefix every booking agent endpoint hangs off. Kept as one constant so
/// the instructions block, OpenAPI, discovery, and the scoped-MCP endpoint
/// allowlist all spell the same path.
pub(crate) const BOOKING_API_PREFIX: &str = "/api/booking";

/// Header a reverse proxy uses to state the visitor address. Absent or
/// unparsable, the request buckets under the unspecified address rather than
/// silently bypassing the per-IP window.
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const REAL_IP_HEADER: &str = "x-real-ip";

/// Stable MCP server identity used when evaluating a scoped-MCP grant. It
/// matches `initialize.serverInfo.name` on the same gateway.
pub(crate) const BOOKING_MCP_SERVER: &str = "oneiron";

/// Attempt-queue lease owner for the request-local lifecycle turn.
const BOOKING_LEASE_OWNER: &str = "oneiron-server/booking-agent-api";

/// Domain tag for the booker contact reference derived from a booker email.
/// Domain-separated so a contact reference can never collide with a lifecycle
/// token digest, a session key, or an anti-abuse hash computed over the same
/// bytes.
const BOOKER_CONTACT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.booker_contact.v1";

/// Domain tag for the anti-abuse identity hashes this adapter derives.
const BOOKING_FACT_DOMAIN: &[u8] = b"oneiron.booking.agent_api.fact.v1";

/// Bound on a booker email accepted at the public door.
const MAX_BOOKER_EMAIL_BYTES: usize = 320;

/// Bound on the opaque session reference a caller may present.
const MAX_SESSION_REF_BYTES: usize = 256;

/// Bound on a single intake answer, and on the whole intake payload.
const MAX_INTAKE_ANSWERS: usize = 32;
const MAX_INTAKE_VALUE_BYTES: usize = 2048;

/// Bound on bounded free text handed to ONE-1816's parser.
const MAX_FREE_TEXT_BYTES: usize = 4096;

// -------------------------------------------------------------------------
// Transport context
// -------------------------------------------------------------------------

/// Which door a booking operation arrived through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BookingTransport {
    PublicHttp,
    Mcp,
}

/// Server-local request context. `authenticated_actor_ref` is deliberately
/// server-local: it never appears in a public DTO and never reaches the engine
/// as a booking subject.
pub(crate) struct BookingTransportContext {
    pub source_ip: IpAddr,
    pub authenticated_actor_ref: Option<oneiron::EntityId>,
    pub transport: BookingTransport,
}

impl BookingTransportContext {
    fn public_http(headers: &HeaderMap) -> Self {
        Self {
            source_ip: source_ip(headers),
            authenticated_actor_ref: None,
            transport: BookingTransport::PublicHttp,
        }
    }

    /// The MCP context. A connector call carries no visitor address, so the
    /// per-IP window buckets on the unspecified address and the actor binding
    /// carries the real identity.
    pub(crate) const fn mcp(actor_ref: oneiron::EntityId) -> Self {
        Self {
            source_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            authenticated_actor_ref: Some(actor_ref),
            transport: BookingTransport::Mcp,
        }
    }
}

/// Reads the visitor address a trusted reverse proxy stated.
fn source_ip(headers: &HeaderMap) -> IpAddr {
    for name in [FORWARDED_FOR_HEADER, REAL_IP_HEADER] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            // `X-Forwarded-For` is a client-to-proxy chain; the first entry is
            // the originating client.
            let candidate = value.split(',').next().unwrap_or("").trim();
            if let Ok(parsed) = candidate.parse::<IpAddr>() {
                return parsed;
            }
        }
    }
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

// -------------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------------

/// The booking agent surface. Registered as a sub-router so `api.rs` gains one
/// merge rather than five route literals.
///
/// Every route is public by design: a visiting agent has no Oneiron credential,
/// and ONE-1817's caps — not a bearer check — are what bound the surface.
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

/// Canonical relative endpoint path for one operation on one page token.
#[must_use]
pub(crate) fn booking_operation_path(page_token: &str, operation: BookingAgentOperation) -> String {
    format!("{BOOKING_API_PREFIX}/{page_token}/{}", operation.as_str())
}

/// The canonical endpoint identifier a scoped-MCP grant allowlists. It is the
/// path TEMPLATE, not one page's concrete path: a grant authorizes an
/// operation, not a single booking page.
#[must_use]
pub(crate) fn booking_operation_endpoint(operation: BookingAgentOperation) -> String {
    format!("{BOOKING_API_PREFIX}/{{page_token}}/{}", operation.as_str())
}

// -------------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------------

/// `GET /api/booking/{page_token}/agent-instructions`
///
/// Returns the exact JSON document the public page fragment embeds.
#[utoipa::path(
    get,
    path = "/api/booking/{page_token}/agent-instructions",
    params(("page_token" = String, Path, description = "Opaque booking page token; never an internal entity id.")),
    responses(
        (status = 200, description = "Versioned agent instructions for this booking page.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed page token.", body = ApiError),
        (status = 404, description = "No booking page resolves for this token.", body = ApiError)
    ),
    tag = "booking"
)]
pub(crate) async fn booking_agent_instructions(
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let block = booking_agent_instructions_block(&server, &page_token)?;
    // The endpoint serves the SAME canonical bytes the embedded fragment
    // decodes to, because both read `canonical_instructions_json`. Serializing
    // the block a second time here would be a second contract.
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        canonical_instructions_json(&block)?,
    ))
}

/// `POST /api/booking/{page_token}/availability`
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/availability",
    params(("page_token" = String, Path, description = "Opaque booking page token; never an internal entity id.")),
    request_body(content = Object, description = "BookingAvailabilityInput: event_type, window, visitor_tz, optional tagged constraint, session_ref.", content_type = "application/json"),
    responses(
        (status = 200, description = "Ranked UTC slots and the flex flag. No calendar detail crosses this boundary.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed request or unsupported constraint.", body = ApiError),
        (status = 404, description = "No booking page resolves for this token.", body = ApiError),
        (status = 429, description = "ONE-1817 booking caps refused the request.", body = ApiError)
    ),
    tag = "booking"
)]
pub(crate) async fn booking_availability(
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    headers: HeaderMap,
    Json(input): Json<BookingAvailabilityInput>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = BookingTransportContext::public_http(&headers);
    let response = execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Availability(input),
        &transport,
    )
    .await?;
    Ok(Json(response))
}

/// `POST /api/booking/{page_token}/book`
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/book",
    params(("page_token" = String, Path, description = "Opaque booking page token; never an internal entity id.")),
    request_body(content = Object, description = "BookingBookInput: a tagged hold|confirm stage. hold carries no TTL; confirm carries the opaque hold token.", content_type = "application/json"),
    responses(
        (status = 200, description = "held (opaque hold token plus server-capped expiry), confirmed (reschedule and cancel tokens), or slot_taken with alternatives.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed request or refused stage.", body = ApiError),
        (status = 404, description = "No booking page resolves for this token.", body = ApiError),
        (status = 429, description = "ONE-1817 booking caps refused the request.", body = ApiError)
    ),
    tag = "booking"
)]
pub(crate) async fn booking_book(
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    headers: HeaderMap,
    Json(input): Json<BookingBookInput>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = BookingTransportContext::public_http(&headers);
    let response = execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Book(input),
        &transport,
    )
    .await?;
    Ok(Json(response))
}

/// `POST /api/booking/{page_token}/reschedule`
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/reschedule",
    params(("page_token" = String, Path, description = "Opaque booking page token; never an internal entity id.")),
    request_body(content = Object, description = "BookingRescheduleInput: the action-scoped reschedule_token plus the new slot.", content_type = "application/json"),
    responses(
        (status = 200, description = "The action-scoped reschedule token for the moved booking.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed, expired, or wrong-action token.", body = ApiError),
        (status = 404, description = "No booking page resolves for this token.", body = ApiError),
        (status = 429, description = "ONE-1817 booking caps refused the request.", body = ApiError)
    ),
    tag = "booking"
)]
pub(crate) async fn booking_reschedule(
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    headers: HeaderMap,
    Json(input): Json<BookingRescheduleInput>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = BookingTransportContext::public_http(&headers);
    let response = execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Reschedule(input),
        &transport,
    )
    .await?;
    Ok(Json(response))
}

/// `POST /api/booking/{page_token}/cancel`
#[utoipa::path(
    post,
    path = "/api/booking/{page_token}/cancel",
    params(("page_token" = String, Path, description = "Opaque booking page token; never an internal entity id.")),
    request_body(content = Object, description = "BookingCancelInput: the action-scoped cancel_token.", content_type = "application/json"),
    responses(
        (status = 200, description = "The action-scoped cancel token that was consumed.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed, expired, or wrong-action token.", body = ApiError),
        (status = 404, description = "No booking page resolves for this token.", body = ApiError),
        (status = 429, description = "ONE-1817 booking caps refused the request.", body = ApiError)
    ),
    tag = "booking"
)]
pub(crate) async fn booking_cancel(
    State(server): State<Arc<SyncServer>>,
    Path(page_token): Path<String>,
    headers: HeaderMap,
    Json(input): Json<BookingCancelInput>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let transport = BookingTransportContext::public_http(&headers);
    let response = execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Cancel(input),
        &transport,
    )
    .await?;
    Ok(Json(response))
}

// -------------------------------------------------------------------------
// Instructions block + script-safe fragment
// -------------------------------------------------------------------------

/// Builds the canonical instructions block for one page token.
///
/// The event-type list is the page's own live `booking.event_type`
/// configuration, sorted, so the block never advertises a type the solver would
/// refuse. Nothing else about the configuration crosses the boundary.
///
/// # Errors
///
/// [`ApiError`] bad-request on a malformed token, not-found when no booking
/// page resolves, internal-server on a storage failure.
pub(crate) fn booking_agent_instructions_block(
    server: &SyncServer,
    page_token: &str,
) -> Result<BookingAgentInstructionsBlock, ApiError> {
    let page_ref = resolve_page_token(server, page_token)?;
    let mut event_types = page_event_types(server, page_ref)?;
    event_types.sort_by(|left, right| left.0.cmp(&right.0));
    event_types.dedup_by(|left, right| left.0 == right.0);

    let block = BookingAgentInstructionsBlock {
        version: BOOKING_AGENT_INSTRUCTIONS_VERSION,
        page_token: page_token.to_owned(),
        event_types,
        operations: BookingAgentOperation::CANONICAL_ORDER
            .iter()
            .map(|operation| BookingAgentEndpoint {
                operation: *operation,
                method: "POST".to_owned(),
                path: booking_operation_path(page_token, *operation),
            })
            .collect(),
        constraint_schema_version: oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION,
    };
    block.validate().map_err(|defect| {
        ApiError::bad_request(defect.to_string(), Some("page_token"))
    })?;
    Ok(block)
}

/// Renders the embeddable, script-safe fragment ONE-1815 inserts verbatim.
///
/// The escaping is what makes the block machinery rather than a template hole:
/// `</script`, U+2028, and U+2029 are rewritten as JSON string escapes, so a
/// hostile page token or event-type key cannot terminate the element or break
/// the surrounding script context. The decoded JSON is byte-identical to the
/// document the `agent-instructions` endpoint serves.
///
/// # Errors
///
/// [`ApiError`] internal-server when the block cannot be serialized.
// ONE-1815 owns page rendering and is this function's production consumer: it
// inserts the fragment verbatim and may style around it, but cannot mutate the
// versioned JSON contract. Until that renderer lands the non-test build has no
// caller — the same `reactive` posture `booking_anti_abuse` carried while its
// own consumers were pending.
#[allow(dead_code)]
pub(crate) fn render_booking_agent_instructions_block(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    let json = canonical_instructions_json(block)?;
    Ok(format!(
        "<script type=\"{BOOKING_AGENT_INSTRUCTIONS_MIME}\">{}</script>",
        script_safe_json(&json)
    ))
}

/// The one canonical serialization of the block. Both the fragment and the HTTP
/// endpoint read it, so they cannot drift.
///
/// # Errors
///
/// [`ApiError`] internal-server when the block cannot be serialized.
pub(crate) fn canonical_instructions_json(
    block: &BookingAgentInstructionsBlock,
) -> Result<String, ApiError> {
    serde_json::to_string(block).map_err(|_| {
        ApiError::internal_server_error("booking agent instructions could not be serialized")
    })
}

/// Rewrites the sequences that can escape a `<script>` element or a JavaScript
/// string literal. Every replacement is a JSON string escape, so the decoded
/// value is unchanged.
// Live once ONE-1815's renderer calls the fragment builder above.
#[allow(dead_code)]
fn script_safe_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        match ch {
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
// Shared executor
// -------------------------------------------------------------------------

/// The ONE place a booking operation runs, for every transport.
///
/// Mandatory order:
/// 1. Validate the opaque page token, caller keys, and operation shape, and
///    resolve the page subject internally.
/// 2. Call ONE-1817's admission API EXACTLY ONCE, with the operation's own
///    class. No caller or gateway pre-checks it, and a refusal short-circuits
///    before any parse, solve, or lifecycle work.
/// 3. Replace bounded free text with a canonical `ConstraintObject` through
///    ONE-1816's parser seam; the sentence never reaches the oracle.
/// 4. Dispatch to the merged solver or to the ONE-1813 lifecycle door, whose
///    home-node writer revalidates every mutation.
/// 5. Project only operation-safe data.
///
/// `server` is the `Arc` the handlers thread from `State<Arc<SyncServer>>`,
/// because ONE-1817's admission API is itself extractor-shaped
/// (`State<Arc<SyncServer>>`) and this executor owns its only call.
///
/// # Errors
///
/// [`ApiError`] for a malformed request, an unresolvable page, a capped
/// request, or an engine failure.
pub(crate) async fn execute_booking_operation(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    transport: &BookingTransportContext,
) -> Result<BookingOperationResponse, ApiError> {
    // ── 1. Shape and subject ────────────────────────────────────────────
    let page_ref = resolve_page_token(server, page_token)?;
    validate_request_shape(&request)?;
    let now = now_secs()?;

    // ── 2. The one and only BK-06 admission call ────────────────────────
    let facts = booking_request_facts(server, page_ref, &request, transport, now)?;
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
    if let Some(refusal) = admission_refusal(&request, disposition) {
        return refusal;
    }

    // ── 3-5. Parse, dispatch, project ───────────────────────────────────
    match request {
        BookingOperationRequest::Availability(input) => {
            solve_availability(server, page_ref, input, now)
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            run_hold(server, page_ref, input, now)
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            run_confirm(server, page_ref, input, now)
        }
        BookingOperationRequest::Reschedule(input) => {
            run_reschedule(server, page_ref, input, now)
        }
        BookingOperationRequest::Cancel(input) => run_cancel(server, page_ref, input, now),
    }
}

/// Translates a non-`Continue` admission disposition into the answer the caller
/// sees, or `None` when the request may proceed.
///
/// `SilentOk` and `QuarantineAndAccept` are deliberately indistinguishable from
/// an ordinary success at the surface: they answer with the operation's empty
/// shape and perform no booking-side work.
fn admission_refusal(
    request: &BookingOperationRequest,
    disposition: BookingHttpDisposition,
) -> Option<Result<BookingOperationResponse, ApiError>> {
    match disposition {
        BookingHttpDisposition::Continue => None,
        BookingHttpDisposition::SilentOk | BookingHttpDisposition::QuarantineAndAccept => {
            Some(Ok(silent_ok_response(request)))
        }
        // The closed error catalog carries exactly one 429 code, so a booking
        // cap refusal reuses it rather than growing the vocabulary. The retry
        // hint travels in `reset_at`, which is what a client needs.
        BookingHttpDisposition::RetryAfter { seconds } => Some(Err(ApiError::new(
            format!("booking requests are rate limited; retry after {seconds} seconds"),
            crate::error::ApiErrorDetails::DailyBudgetExhausted {
                limit: None,
                used: None,
                reset_at: Some(seconds.to_string()),
            },
            [format!("Wait {seconds} seconds and retry the same request.")],
        ))),
        BookingHttpDisposition::PromptCorrection { body } => Some(Err(ApiError::bad_request(
            body,
            Some("booker_email"),
        ))),
    }
}

/// The shape a silently-rejected or quarantined request answers with: the
/// operation's own empty projection, never a distinguishable error.
fn silent_ok_response(request: &BookingOperationRequest) -> BookingOperationResponse {
    match request {
        BookingOperationRequest::Availability(_) => BookingOperationResponse::Availability {
            slots: Vec::new(),
            flex_used: false,
        },
        BookingOperationRequest::Book(_) => BookingOperationResponse::Book {
            result: BookingBookResult::SlotTaken {
                alternatives: Vec::new(),
            },
        },
        BookingOperationRequest::Reschedule(input) => BookingOperationResponse::Reschedule {
            reschedule_token: input.reschedule_token.clone(),
        },
        BookingOperationRequest::Cancel(input) => BookingOperationResponse::Cancel {
            cancel_token: input.cancel_token.clone(),
        },
    }
}

// -------------------------------------------------------------------------
// Step 1 — shape validation and page resolution
// -------------------------------------------------------------------------

/// Refuses a request whose caller keys are absent, over-long, or shaped like an
/// internal identifier, before anything reads the vault.
fn validate_request_shape(request: &BookingOperationRequest) -> Result<(), ApiError> {
    match request {
        BookingOperationRequest::Availability(input) => {
            validate_session_ref(&input.session_ref)?;
            if input.window.start >= input.window.end {
                return Err(ApiError::bad_request(
                    "availability window must satisfy start < end",
                    Some("window"),
                ));
            }
            if let Some(BookingConstraintInput::FreeText(text)) = &input.constraint {
                if text.trim().is_empty() || text.len() > MAX_FREE_TEXT_BYTES {
                    return Err(ApiError::bad_request(
                        format!("constraint free text must be 1..={MAX_FREE_TEXT_BYTES} bytes"),
                        Some("constraint"),
                    ));
                }
            }
            Ok(())
        }
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            validate_session_ref(&input.session_ref)?;
            validate_idempotency_key(&input.idempotency_key)?;
            validate_selected_slot(input.selected_slot)?;
            if let Some(lease) = &input.checkout_lease_token {
                validate_opaque_token(lease, "checkout_lease_token")?;
            }
            Ok(())
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            validate_session_ref(&input.session_ref)?;
            validate_idempotency_key(&input.idempotency_key)?;
            validate_opaque_token(&input.hold_token, "hold_token")?;
            validate_booker_email(&input.booker_email)?;
            if input.intake.len() > MAX_INTAKE_ANSWERS {
                return Err(ApiError::bad_request(
                    format!("intake carries at most {MAX_INTAKE_ANSWERS} answers"),
                    Some("intake"),
                ));
            }
            if input
                .intake
                .iter()
                .any(|answer| answer.value.len() > MAX_INTAKE_VALUE_BYTES)
            {
                return Err(ApiError::bad_request(
                    format!("intake answer must be at most {MAX_INTAKE_VALUE_BYTES} bytes"),
                    Some("intake"),
                ));
            }
            Ok(())
        }
        BookingOperationRequest::Reschedule(input) => {
            validate_idempotency_key(&input.idempotency_key)?;
            validate_opaque_token(&input.reschedule_token, "reschedule_token")?;
            validate_selected_slot(input.selected_slot)
        }
        BookingOperationRequest::Cancel(input) => {
            validate_idempotency_key(&input.idempotency_key)?;
            validate_opaque_token(&input.cancel_token, "cancel_token")
        }
    }
}

fn validate_selected_slot(slot: SelectedSlot) -> Result<(), ApiError> {
    if slot.start_utc >= slot.end_utc {
        return Err(ApiError::bad_request(
            "selected slot must satisfy start_utc < end_utc",
            Some("selected_slot"),
        ));
    }
    Ok(())
}

fn validate_session_ref(session_ref: &str) -> Result<(), ApiError> {
    if session_ref.trim().is_empty() || session_ref.len() > MAX_SESSION_REF_BYTES {
        return Err(ApiError::bad_request(
            format!("session_ref must be 1..={MAX_SESSION_REF_BYTES} non-blank bytes"),
            Some("session_ref"),
        ));
    }
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<(), ApiError> {
    if key.trim().is_empty() || key.len() > 128 {
        return Err(ApiError::bad_request(
            "idempotency_key must be 1..=128 non-blank bytes",
            Some("idempotency_key"),
        ));
    }
    Ok(())
}

/// An action-scoped bearer token is opaque, bounded, and never an entity id.
/// Refusing the entity-id shape here is what makes "an internal id is not a
/// token" a mechanical property rather than a convention.
fn validate_opaque_token(token: &str, field: &'static str) -> Result<(), ApiError> {
    if token.trim().is_empty() || token.len() > 256 {
        return Err(ApiError::bad_request(
            format!("{field} must be 1..=256 non-blank bytes"),
            Some(field),
        ));
    }
    if is_entity_id_shaped(token) {
        return Err(ApiError::bad_request(
            format!("{field} must be an action-scoped token, not an internal identifier"),
            Some(field),
        ));
    }
    Ok(())
}

fn validate_booker_email(email: &str) -> Result<(), ApiError> {
    let trimmed = email.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_BOOKER_EMAIL_BYTES {
        return Err(ApiError::bad_request(
            format!("booker_email must be 1..={MAX_BOOKER_EMAIL_BYTES} non-blank bytes"),
            Some("booker_email"),
        ));
    }
    Ok(())
}

fn is_entity_id_shaped(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Resolves the opaque page token to its internal subject.
///
/// The token is the page's presentation id (`shortId:contentHash`) — the
/// engine's existing public addressing scheme. A raw 32-hex entity id is
/// refused outright: no public handler may accept an internal page identifier,
/// so presenting one is a request defect rather than a shortcut.
///
/// # Errors
///
/// [`ApiError`] bad-request on a malformed token, not-found when nothing
/// resolves, internal-server on a storage failure.
pub(crate) fn resolve_page_token(
    server: &SyncServer,
    page_token: &str,
) -> Result<oneiron::EntityId, ApiError> {
    let token = page_token.trim();
    if token.is_empty() {
        return Err(ApiError::bad_request(
            "page_token must not be blank",
            Some("page_token"),
        ));
    }
    if is_entity_id_shaped(token) {
        return Err(ApiError::bad_request(
            "page_token must be an opaque booking page token, not an internal entity id",
            Some("page_token"),
        ));
    }
    let (short_id, content_hash) = super::parse_short_ref(token)?;
    let hydrated = server
        .vault
        .hydrate_short_id(&short_id, content_hash)
        .map_err(|_| ApiError::internal_server_error("booking page lookup failed"))?;
    match hydrated {
        Some(entry) if entry.body.is_some() => Ok(entry.id),
        _ => Err(ApiError::not_found("booking page", Some("page_token"))),
    }
}

/// The event types this page publishes, read from its live `booking.event_type`
/// configuration claims.
///
/// Surfaceability is the engine's own truth table — auto/approved, active, not
/// stale — applied to the public `ClaimBody` fields, so a proposed or
/// superseded configuration is never advertised.
fn page_event_types(
    server: &SyncServer,
    page_ref: oneiron::EntityId,
) -> Result<Vec<oneiron::EventTypeKey>, ApiError> {
    Ok(page_event_type_configs(server, page_ref)?
        .into_iter()
        .map(|config| config.key)
        .collect())
}

/// The page's live event-type configurations.
fn page_event_type_configs(
    server: &SyncServer,
    page_ref: oneiron::EntityId,
) -> Result<Vec<oneiron::EventTypeConfig>, ApiError> {
    let vault = &server.vault;
    let claim_ids = vault
        .claims_for_subject(&page_ref)
        .map_err(|_| ApiError::internal_server_error("booking page configuration read failed"))?;
    let mut configs = Vec::new();
    for claim_id in claim_ids {
        let Some(body) = vault
            .get_claim(&claim_id)
            .map_err(|_| ApiError::internal_server_error("booking page configuration read failed"))?
        else {
            continue;
        };
        if body.predicate != oneiron::BOOKING_EVENT_TYPE_PREDICATE
            || body.subject != oneiron::ClaimSubject::Entity(page_ref)
            || !claim_is_surfaceable(&body)
        {
            continue;
        }
        // Past this point the row IS one of this page's configuration claims,
        // so a malformed body is skipped rather than failing the whole page:
        // one broken event type must not hide the others.
        if let Ok(decoded) = oneiron::decode_event_type_claim_value(&body.value) {
            configs.push(decoded.config);
        }
    }
    Ok(configs)
}

/// The engine's surfaceable truth table, expressed over the public claim body
/// fields (`crate::claim::claim_surfaceable` is engine-private).
fn claim_is_surfaceable(body: &oneiron::ClaimBody) -> bool {
    matches!(
        body.approval,
        oneiron::ClaimApprovalStatus::Auto | oneiron::ClaimApprovalStatus::Approved
    ) && body.lifecycle == oneiron::ClaimLifecycleStatus::Active
        && !body.stale
}

// -------------------------------------------------------------------------
// Step 2 — anti-abuse facts
// -------------------------------------------------------------------------

/// Builds the ONE-1817 fact row for this request.
///
/// Identity material is hashed at this trusted boundary: no raw address, email,
/// or session reference reaches the anti-abuse module or its storage. The
/// submission fingerprint is left zeroed on purpose — `enforce_book` overwrites
/// it with the server-derived value and never honours a transport-supplied one.
fn booking_request_facts(
    server: &SyncServer,
    page_ref: oneiron::EntityId,
    request: &BookingOperationRequest,
    transport: &BookingTransportContext,
    now: u64,
) -> Result<BookingRequestFacts, ApiError> {
    let now_millis = now.saturating_mul(1000);
    let event_type = match request {
        BookingOperationRequest::Availability(input) => Some(input.event_type.clone()),
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            Some(input.event_type.clone())
        }
        _ => None,
    };
    let session_ref = match request {
        BookingOperationRequest::Availability(input) => Some(input.session_ref.as_str()),
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => {
            Some(input.session_ref.as_str())
        }
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            Some(input.session_ref.as_str())
        }
        BookingOperationRequest::Reschedule(_) | BookingOperationRequest::Cancel(_) => None,
    };
    let email = match request {
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            Some(normalized_email(&input.booker_email))
        }
        _ => None,
    };

    let session_key = session_ref.map(|value| oneiron::SessionKey::derive(value.as_bytes()));
    let active_holds_for_session = match (session_key, request) {
        (Some(session_key), BookingOperationRequest::Book(BookingBookInput::Hold(input))) => {
            active_holds_for_session(server, page_ref, session_key, input.selected_slot, now)?
        }
        _ => 0,
    };

    // The per-request rate identity. A public visitor is bucketed by address; a
    // connector has no visitor address, so its AUTHENTICATED actor is its
    // bucket. Both transports therefore reach the same evaluator with a real,
    // non-degenerate key rather than sharing one unspecified-address bucket.
    let ip_hash = match transport.transport {
        BookingTransport::PublicHttp => {
            fact_hash(b"ip", transport.source_ip.to_string().as_bytes())
        }
        BookingTransport::Mcp => match transport.authenticated_actor_ref {
            Some(actor_ref) => fact_hash(b"mcp-actor", actor_ref.as_bytes()),
            None => fact_hash(b"ip", transport.source_ip.to_string().as_bytes()),
        },
    };

    Ok(BookingRequestFacts {
        page_ref,
        event_type,
        ip_hash,
        email_hash: email
            .as_deref()
            .map(|value| fact_hash(b"email", value.as_bytes())),
        session_hash: session_ref.map(|value| fact_hash(b"session", value.as_bytes())),
        started_at_millis: now_millis,
        submitted_at_millis: now_millis,
        // Overwritten by the trusted admission boundary in `enforce_book`.
        submission_fingerprint: [0_u8; 32],
        selected_slot_hash: selected_slot_hash(request),
        intake_content_hash: intake_content_hash(request),
        // The engine's honeypot lives on the ONE-1815 rendered form, not on the
        // machine surface: an agent submits no decoy field.
        honeypot_nonempty: false,
        intake_chars: intake_chars(request),
        // STACK SEAM: the confirmed-booking count per booker email has no public
        // reader on this head — ONE-1813's rows are session-keyed and the count
        // door is engine-private. Zero is the honest value here, and it never
        // relaxes a configured cap: the per-IP/email rate window and the
        // quarantine path still run.
        active_future_bookings_for_email: 0,
        active_holds_for_session,
        email: email.as_deref().map(email_validation_evidence),
    })
}

/// Counts this session's own live holds by differencing the page's live-hold
/// set against the same set with this session excluded. Both readings come from
/// ONE-1813's `VaultActiveHoldSource`, so the count is the writer's truth
/// rather than a second hold store.
fn active_holds_for_session(
    server: &SyncServer,
    page_ref: oneiron::EntityId,
    session_key: oneiron::SessionKey,
    slot: SelectedSlot,
    now: u64,
) -> Result<u8, ApiError> {
    use oneiron::ActiveHoldSource;

    let vault: &oneiron::Vault = &server.vault;
    let window = oneiron::TimeRange {
        start: slot.start_utc,
        end: slot.end_utc,
    };
    let source = oneiron::VaultActiveHoldSource::new(vault);
    let all = source
        .active_holds(page_ref, window, now, None)
        .map_err(|_| ApiError::internal_server_error("booking hold lookup failed"))?
        .len();
    let others = source
        .active_holds(page_ref, window, now, Some(&session_key.0))
        .map_err(|_| ApiError::internal_server_error("booking hold lookup failed"))?
        .len();
    Ok(u8::try_from(all.saturating_sub(others)).unwrap_or(u8::MAX))
}

fn normalized_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Structural email evidence only. No DNS lookup and no disposable-domain list
/// is introduced here: MX presence stays `None` (unknown), which is what lets
/// ONE-1817 prompt a correction instead of hard-blocking.
fn email_validation_evidence(email: &str) -> EmailValidationEvidence {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    let syntax_valid = !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.contains(char::is_whitespace);
    EmailValidationEvidence {
        syntax_valid,
        mx_present: None,
        disposable_domain: false,
    }
}

fn fact_hash(tag: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BOOKING_FACT_DOMAIN);
    hasher.update(tag);
    hasher.update(material);
    *hasher.finalize().as_bytes()
}

fn selected_slot_hash(request: &BookingOperationRequest) -> [u8; 32] {
    let slot = match request {
        BookingOperationRequest::Book(BookingBookInput::Hold(input)) => Some(input.selected_slot),
        BookingOperationRequest::Reschedule(input) => Some(input.selected_slot),
        _ => None,
    };
    match slot {
        Some(slot) => {
            let mut material = Vec::with_capacity(16);
            material.extend_from_slice(&slot.start_utc.to_be_bytes());
            material.extend_from_slice(&slot.end_utc.to_be_bytes());
            fact_hash(b"slot", &material)
        }
        None => [0_u8; 32],
    }
}

fn intake_content_hash(request: &BookingOperationRequest) -> [u8; 32] {
    match request {
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => {
            let mut material = Vec::new();
            for answer in &input.intake {
                material.extend_from_slice(answer.field_key.as_bytes());
                material.push(0);
                material.extend_from_slice(answer.value.as_bytes());
                material.push(0);
            }
            fact_hash(b"intake", &material)
        }
        _ => [0_u8; 32],
    }
}

fn intake_chars(request: &BookingOperationRequest) -> usize {
    match request {
        BookingOperationRequest::Book(BookingBookInput::Confirm(input)) => input
            .intake
            .iter()
            .map(|answer| answer.value.chars().count())
            .sum(),
        _ => 0,
    }
}

// -------------------------------------------------------------------------
// Step 3 — constraint normalization
// -------------------------------------------------------------------------

/// Replaces caller input with a canonical [`oneiron::ConstraintObject`].
///
/// A prebuilt object bypasses parsing but is still canonicalized and validated,
/// so two semantically identical payloads reach the oracle as the same bytes.
///
/// `FreeText` is the ONE-1816 parser seam. That parser is a bounded, tiered
/// model call, and this server binds no parse tier on this head, so free text
/// fails CLOSED here. What matters structurally is what cannot happen either
/// way: the sentence is consumed at this boundary and
/// [`oneiron::SolveRequest`] has no field it could ride into a solve.
fn normalize_constraint(
    input: Option<BookingConstraintInput>,
) -> Result<Option<oneiron::ConstraintObject>, ApiError> {
    match input {
        None => Ok(None),
        Some(BookingConstraintInput::Object(object)) => object
            .canonicalize()
            .map(Some)
            .map_err(|error| ApiError::bad_request(error.to_string(), Some("constraint"))),
        Some(BookingConstraintInput::FreeText(_)) => Err(ApiError::bad_request(
            "free-text scheduling preferences require a configured booking constraint parse tier; \
             send a structured constraint object instead",
            Some("constraint"),
        )),
    }
}

// -------------------------------------------------------------------------
// Step 4 — solver and lifecycle dispatch
// -------------------------------------------------------------------------

/// The page's availability oracle.
///
/// It OWNS its hold source so it can be built inside the lifecycle's
/// `make_oracle` callback, where a `BookingSolver` borrowing a local would not
/// outlive the call.
struct PageOracle<'a> {
    vault: &'a oneiron::Vault,
    page_ref: oneiron::EntityId,
    calendars_by_host: Vec<(oneiron::EntityId, Vec<oneiron::CalendarSel>)>,
    holds: oneiron::VaultActiveHoldSource<'a>,
    now_utc: u64,
}

impl oneiron::SlotOracle for PageOracle<'_> {
    fn solve(
        &self,
        req: &oneiron::SolveRequest,
    ) -> Result<oneiron::SolveResult, oneiron::BookingError> {
        let solver = oneiron::BookingSolver {
            vault: self.vault,
            page_ref: self.page_ref,
            calendars_by_host: &self.calendars_by_host,
            holds: &self.holds,
            now_utc: self.now_utc,
            // `None` is the load-bearing value: the configuration resolves from
            // the page's own `booking.event_type` claim. Only ONE-1821's
            // page-less companion presets carry a synthetic configuration.
            synthetic_config: None,
        };
        oneiron::SlotOracle::solve(&solver, req)
    }
}

/// Binds every configured host to its calendar selectors.
///
/// The solver refuses an unbound host and an empty selector slice alike, so
/// this binding is explicit rather than defaulted. `CalendarSel::system`
/// filtering is deferred to CAL-02's passport index (ONE-1784); until it lands
/// a well-formed selector must not empty the union, so one unfiltered selector
/// per configured host is the binding that matches the current calendar
/// baseline.
fn page_calendar_bindings(
    server: &SyncServer,
    page_ref: oneiron::EntityId,
) -> Result<Vec<(oneiron::EntityId, Vec<oneiron::CalendarSel>)>, ApiError> {
    let mut bindings: Vec<(oneiron::EntityId, Vec<oneiron::CalendarSel>)> = Vec::new();
    for config in page_event_type_configs(server, page_ref)? {
        for host in config.hosts {
            if bindings.iter().any(|(id, _)| *id == host.host_ref) {
                continue;
            }
            bindings.push((host.host_ref, vec![oneiron::CalendarSel { system: None }]));
        }
    }
    Ok(bindings)
}

/// Availability: the merged solver, projected to the public slot artifact.
fn solve_availability(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    input: BookingAvailabilityInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let vault: &oneiron::Vault = &server.vault;
    let constraint = normalize_constraint(input.constraint)?;
    let oracle = PageOracle {
        vault,
        page_ref,
        calendars_by_host: page_calendar_bindings(server, page_ref)?,
        holds: oneiron::VaultActiveHoldSource::new(vault),
        now_utc: now,
    };
    let solved = oneiron::SlotOracle::solve(
        &oracle,
        &oneiron::SolveRequest {
            event_type: input.event_type,
            window: input.window,
            constraint,
            visitor_tz: input.visitor_tz,
        })
        .map_err(booking_engine_error)?;
    Ok(BookingOperationResponse::Availability {
        slots: solved.slots,
        flex_used: solved.flex_used,
    })
}

/// `book:hold` — the lifecycle hold verb. No caller TTL exists to forward; the
/// only lifetime input is an optional server-issued checkout lease.
fn run_hold(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    input: BookingHoldInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let session_key = oneiron::SessionKey::derive(input.session_ref.as_bytes());
    let constraint = input
        .constraint
        .map(oneiron::ConstraintObject::canonicalize)
        .transpose()
        .map_err(|error| ApiError::bad_request(error.to_string(), Some("constraint")))?;
    let lease = match input.checkout_lease_token {
        None => oneiron::HoldLeaseSpec::Ordinary,
        Some(token) => oneiron::HoldLeaseSpec::CheckoutExtension {
            server_issued_lease: oneiron::OpaqueCheckoutLeaseToken(token),
        },
    };
    let receipt = run_booking_verb(
        server,
        page_ref,
        Some(session_key),
        oneiron::BookingVerbRequest::Hold(oneiron::HoldSpec {
            page_ref,
            event_type: input.event_type,
            slot: oneiron::TimeRange {
                start: input.selected_slot.start_utc,
                end: input.selected_slot.end_utc,
            },
            session_key,
            visitor_tz: input.visitor_tz,
            constraint,
            lease,
            idempotency_key: Some(input.idempotency_key),
        }),
        now,
    )?;
    match receipt {
        oneiron::BookingVerbReceipt::Held(held) => Ok(BookingOperationResponse::Book {
            result: BookingBookResult::Held {
                hold_token: held.token.0,
                selected_slot: SelectedSlot {
                    start_utc: held.slot.start,
                    end_utc: held.slot.end,
                },
                expires_at: held.expires_at,
            },
        }),
        oneiron::BookingVerbReceipt::SlotTaken { alternatives } => {
            Ok(BookingOperationResponse::Book {
                result: BookingBookResult::SlotTaken { alternatives },
            })
        }
        _ => Err(ApiError::internal_server_error(
            "booking hold returned an unexpected lifecycle receipt",
        )),
    }
}

/// `book:confirm` — consumes the opaque hold token and returns the two distinct
/// action-scoped tokens the lifecycle derived for this booking.
fn run_confirm(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    input: BookingConfirmInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let session_key = oneiron::SessionKey::derive(input.session_ref.as_bytes());
    let receipt = run_booking_verb(
        server,
        page_ref,
        Some(session_key),
        oneiron::BookingVerbRequest::Confirm(oneiron::ConfirmSpec {
            hold_token: oneiron::OpaqueLifecycleToken(input.hold_token),
            session_key,
            booker_contact: booker_contact_ref(&input.booker_email)?,
            idempotency_key: Some(input.idempotency_key),
        }),
        now,
    )?;
    match receipt {
        oneiron::BookingVerbReceipt::Confirmed(confirmed) => Ok(BookingOperationResponse::Book {
            result: BookingBookResult::Confirmed {
                reschedule_token: confirmed.reschedule_token.0,
                cancel_token: confirmed.cancel_token.0,
            },
        }),
        oneiron::BookingVerbReceipt::SlotTaken { alternatives } => {
            Ok(BookingOperationResponse::Book {
                result: BookingBookResult::SlotTaken { alternatives },
            })
        }
        _ => Err(ApiError::internal_server_error(
            "booking confirm returned an unexpected lifecycle receipt",
        )),
    }
}

/// `reschedule` — authority is the action-scoped token and nothing else.
fn run_reschedule(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    input: BookingRescheduleInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let token = input.reschedule_token.clone();
    let receipt = run_booking_verb(
        server,
        page_ref,
        None,
        oneiron::BookingVerbRequest::Reschedule(oneiron::RescheduleSpec {
            token: oneiron::OpaqueLifecycleToken(input.reschedule_token),
            new_slot: oneiron::TimeRange {
                start: input.selected_slot.start_utc,
                end: input.selected_slot.end_utc,
            },
            visitor_tz: input.visitor_tz,
            // A reschedule moves a booking to a slot the caller already chose;
            // it does not re-open constraint negotiation.
            constraint: None,
            idempotency_key: Some(input.idempotency_key),
        }),
        now,
    )?;
    match receipt {
        oneiron::BookingVerbReceipt::Rescheduled(_) => {
            Ok(BookingOperationResponse::Reschedule {
                reschedule_token: token,
            })
        }
        _ => Err(ApiError::internal_server_error(
            "booking reschedule returned an unexpected lifecycle receipt",
        )),
    }
}

/// `cancel` — authority is the action-scoped token and nothing else.
fn run_cancel(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    input: BookingCancelInput,
    now: u64,
) -> Result<BookingOperationResponse, ApiError> {
    let token = input.cancel_token.clone();
    let receipt = run_booking_verb(
        server,
        page_ref,
        None,
        oneiron::BookingVerbRequest::Cancel(oneiron::CancelSpec {
            token: oneiron::OpaqueLifecycleToken(input.cancel_token),
            idempotency_key: Some(input.idempotency_key),
        }),
        now,
    )?;
    match receipt {
        oneiron::BookingVerbReceipt::Cancelled(_) => Ok(BookingOperationResponse::Cancel {
            cancel_token: token,
        }),
        _ => Err(ApiError::internal_server_error(
            "booking cancel returned an unexpected lifecycle receipt",
        )),
    }
}

/// Enqueues one booking verb and drives the home-node writer once.
///
/// This adapter never writes an EVENT, mints a token, or touches a hold: it
/// hands the typed request to ONE-1813's public verb door and asks the same
/// public consumer door for the receipt. The consumer refuses on a node that
/// does not hold the MACRO home-node designation, so correctness stays where
/// ONE-1813 put it — there is no second writer here.
fn run_booking_verb(
    server: &Arc<SyncServer>,
    page_ref: oneiron::EntityId,
    exclude_session_key: Option<oneiron::SessionKey>,
    request: oneiron::BookingVerbRequest,
    now: u64,
) -> Result<oneiron::BookingVerbReceipt, ApiError> {
    let vault: &oneiron::Vault = &server.vault;
    oneiron::enqueue_booking_verb(vault, request, now).map_err(booking_engine_error)?;

    let local_node_id = oneiron::DreamerRunnerStore::new(vault)
        .local_home_node_candidate(false, false, false)
        .map_err(|_| ApiError::internal_server_error("booking node identity unavailable"))?
        .node_id;
    let bindings = page_calendar_bindings(server, page_ref)?;

    let turn = oneiron::run_booking_lifecycle_once(
        vault,
        |oracle_request| {
            Ok(PageOracle {
                vault,
                page_ref: oracle_request.page_ref.unwrap_or(page_ref),
                calendars_by_host: bindings.clone(),
                holds: oneiron::VaultActiveHoldSource {
                    vault,
                    exclude_session_key: oracle_request
                        .exclude_session_key
                        .or(exclude_session_key),
                },
                now_utc: now,
            })
        },
        &oneiron::BookingLifecycleConsumerInput {
            local_node_id,
            lease_owner: BOOKING_LEASE_OWNER.to_owned(),
            now_utc: now,
        },
    )
    .map_err(booking_engine_error)?;

    match turn {
        oneiron::BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
        oneiron::BookingLifecycleTurn::NoHomeNode
        | oneiron::BookingLifecycleTurn::NotHomeNode { .. } => Err(ApiError::new(
            "booking writes are served by this vault's home node",
            crate::error::ApiErrorDetails::InvalidState {
                state: Some("booking_home_node_elsewhere".to_owned()),
            },
            ["Retry against the vault's elected booking home node."],
        )),
        oneiron::BookingLifecycleTurn::Empty => Err(ApiError::internal_server_error(
            "booking lifecycle attempt was not claimed",
        )),
        _ => Err(ApiError::internal_server_error(
            "booking lifecycle returned an unsupported turn",
        )),
    }
}

/// The stable, deterministic contact reference for one booker email.
///
/// This is ONE-1816's email-continuity property expressed as a reference value:
/// the same booker resolves to the same contact reference across bookings, so
/// the lifecycle's `booking.booker_contact` claim is continuous. It ALLOCATES
/// NOTHING — no entity is written, no type byte is claimed, and no registry row
/// is touched. Domain separation keeps it disjoint from every lifecycle token,
/// session key, and anti-abuse hash.
fn booker_contact_ref(email: &str) -> Result<oneiron::EntityId, ApiError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BOOKER_CONTACT_DOMAIN);
    hasher.update(normalized_email(email).as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    if bytes == [0_u8; 16] {
        bytes[0] = 1;
    }
    oneiron::EntityId::from_bytes(bytes)
        .map_err(|_| ApiError::internal_server_error("booker contact reference could not be derived"))
}

/// Maps a typed engine booking error onto the public vocabulary.
///
/// A constraint or configuration defect is the caller's to fix; a solver or
/// storage failure is not, and never leaks its internal detail.
fn booking_engine_error(error: oneiron::BookingError) -> ApiError {
    match error {
        oneiron::BookingError::InvalidConstraint(detail) => {
            ApiError::bad_request(detail, Some("constraint"))
        }
        oneiron::BookingError::ConstraintParse(detail) => {
            ApiError::bad_request(detail, Some("constraint"))
        }
        oneiron::BookingError::SessionCapExhausted => ApiError::new(
            "booking session cap exhausted",
            crate::error::ApiErrorDetails::DailyBudgetExhausted {
                limit: None,
                used: None,
                reset_at: None,
            },
            ["Start a new booking session and retry."],
        ),
        other => {
            tracing::warn!(error = %other, "booking agent API engine failure");
            ApiError::internal_server_error("booking request could not be served")
        }
    }
}

fn now_secs() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal_server_error("booking clock unavailable"))
}

// -------------------------------------------------------------------------
// MCP adapter
// -------------------------------------------------------------------------

/// The data class one booking operation's payload carries, used when evaluating
/// a scoped-MCP grant's ceiling.
///
/// Availability is a public projection. Everything else carries or acts on a
/// booker's identity, so it is personal.
#[must_use]
pub(crate) const fn booking_payload_data_class(
    operation: BookingAgentOperation,
) -> oneiron::DataClass {
    match operation {
        BookingAgentOperation::Availability => oneiron::DataClass::Public,
        BookingAgentOperation::Book
        | BookingAgentOperation::Reschedule
        | BookingAgentOperation::Cancel => oneiron::DataClass::Personal,
    }
}

/// Runs one MCP booking operation through the SAME executor the HTTP routes
/// use, and projects the shared response into MCP result content.
///
/// # Errors
///
/// [`ApiError`] from the shared executor, unchanged.
pub(crate) async fn execute_booking_operation_for_mcp(
    server: &Arc<SyncServer>,
    page_token: &str,
    request: BookingOperationRequest,
    actor_ref: oneiron::EntityId,
) -> Result<serde_json::Value, ApiError> {
    let operation = request.operation();
    let transport = BookingTransportContext::mcp(actor_ref);
    let response = execute_booking_operation(server, page_token, request, &transport).await?;
    let structured = serde_json::to_value(&response).map_err(|_| {
        ApiError::internal_server_error("booking response could not be serialized")
    })?;
    Ok(serde_json::json!({
        "op": operation.as_str(),
        "structured": structured,
    }))
}
