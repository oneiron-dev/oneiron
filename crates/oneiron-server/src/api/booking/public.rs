//! Anonymous, published-capability-only booking transport.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::extract::rejection::PathRejection;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, LOCATION, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderValue, StatusCode};
use oneiron::booking::{
    BookingPageLens, BookingPageModel, BookingPagePublication, BookingVerb, DisclosureRung,
    PUBLIC_BOOKING_ROUTE_PREFIX, PublicBookingAction, PublicBookingPageToken, SurfaceClass,
    load_public_booking_page, project_at_rung, slot_mask,
};

use super::*;

// -------------------------------------------------------------------------
// Public booking boundary (ONE-1815)
// -------------------------------------------------------------------------

/// Exactly two public resources. This router has no generic resource fallback.
pub(crate) fn public_booking_router() -> Router<Arc<SyncServer>> {
    let routes = Router::new()
        .route(
            "/{page_token}",
            get(render_public_booking_page)
                .head(public_booking_not_found_response)
                .fallback(public_booking_not_found_response),
        )
        .route(
            "/{page_token}/verbs/{verb}",
            post(invoke_public_booking_verb).fallback(public_booking_not_found_response),
        )
        // This denial fallback is scoped to the public prefix. It cannot
        // replace the authenticated router's fallback or reach a vault route.
        .fallback(public_booking_not_found_response)
        .layer(axum::middleware::map_response(public_booking_response));
    Router::new().nest(PUBLIC_BOOKING_ROUTE_PREFIX, routes)
}

fn public_booking_not_found() -> ApiError {
    ApiError::not_found("booking page", None)
}

async fn public_booking_not_found_response() -> ApiError {
    public_booking_not_found()
}

/// Configuration locates the internal subject; only the durable owner claim
/// grants public access. Every miss has the same response and no token echo.
fn resolve_public_booking_page(
    server: &SyncServer,
    page_token: &str,
) -> Result<(EntityId, BookingPagePublication), ApiError> {
    let page_ref =
        resolve_booking_page(server, page_token).map_err(|_| public_booking_not_found())?;
    let publication = load_public_booking_page(&server.vault, page_ref, now_secs()?)
        .map_err(|_| public_booking_not_found())?
        .ok_or_else(public_booking_not_found)?;
    Ok((page_ref, publication))
}

pub(crate) async fn render_public_booking_page(
    State(server): State<Arc<SyncServer>>,
    peer: Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Path(page_token) = path.map_err(|_| public_booking_not_found())?;
    let (_, publication) = resolve_public_booking_page(&server, &page_token)?;
    let transport = public_http_transport_context(peer)?;
    let session = format!(
        "public-render-{}",
        transport.source_ip.to_string().replace(':', "-")
    );
    let input = publication
        .initial_availability
        .request(now_secs()?, session)?;
    let request = SolveRequest {
        event_type: input.event_type.clone(),
        window: input.window,
        constraint: None,
        visitor_tz: input.visitor_tz.clone(),
    };
    let response = execute_booking_operation(
        &server,
        &page_token,
        BookingOperationRequest::Availability(input),
        &transport,
    )
    .await?;
    let BookingOperationResponse::Availability { slots, flex_used } = response else {
        return Err(ApiError::internal_server_error(
            "booking availability response invariant",
        ));
    };
    // The shared solver produces the data; the existing disclosure seam owns
    // the public clamp and validates its final half-open mask.
    let mask = slot_mask(&request, SolveResult { slots, flex_used });
    let slots = project_at_rung(
        &[],
        DisclosureRung::Slots,
        SurfaceClass::Public,
        Some(&mask),
    )?;
    // Do not emit an obsolete snapshot after an owner revokes or edits it
    // while admission is awaiting. No second admission or solver call.
    let (_, current) = resolve_public_booking_page(&server, &page_token)?;
    if current != publication {
        return Err(public_booking_not_found());
    }
    let model = BookingPageModel::new(
        publication.owner_display,
        publication.event_types,
        slots,
        publication.constraint_field,
        publication.theme,
    )
    .map_err(|defect| {
        tracing::error!(?defect, "public booking model invariant failed");
        ApiError::internal_server_error("public booking model assembly failed")
    })?;
    public_booking_page_json(model, PublicBookingPageToken(page_token)).map(Json)
}

fn public_booking_page_json(
    model: BookingPageModel,
    token: PublicBookingPageToken,
) -> Result<serde_json::Value, ApiError> {
    let card = BookingPageLens::card_with_actions(&model, &token, &[PublicBookingAction::Hold])
        .map_err(|_| ApiError::internal_server_error("public booking lens assembly failed"))?;
    Ok(serde_json::json!({ "model": model, "card": card }))
}

/// A parser-backed allowlist, not a second verb registry.
pub(crate) fn is_booking_pack_verb(verb: &str) -> bool {
    BookingVerb::parse(verb).is_some()
}

fn public_booking_request_verb(request: &BookingOperationRequest) -> Option<BookingVerb> {
    match request {
        BookingOperationRequest::Availability(_) => None,
        BookingOperationRequest::Book(BookingBookInput::Hold(_)) => Some(BookingVerb::Hold),
        BookingOperationRequest::Book(BookingBookInput::Confirm(_)) => Some(BookingVerb::Confirm),
        BookingOperationRequest::Reschedule(_) => Some(BookingVerb::Reschedule),
        BookingOperationRequest::Cancel(_) => Some(BookingVerb::Cancel),
    }
}

fn match_public_booking_verb(
    verb: &str,
    request: &BookingOperationRequest,
) -> Result<(), ApiError> {
    if !is_booking_pack_verb(verb)
        || BookingVerb::parse(verb) != public_booking_request_verb(request)
    {
        return Err(public_booking_not_found());
    }
    Ok(())
}

pub(crate) async fn invoke_public_booking_verb(
    State(server): State<Arc<SyncServer>>,
    peer: Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>,
    path: Result<Path<(String, String)>, PathRejection>,
    payload: Result<Json<BookingOperationRequest>, JsonRejection>,
) -> Result<Json<BookingOperationResponse>, ApiError> {
    let Path((page_token, verb)) = path.map_err(|_| public_booking_not_found())?;
    // Unknown verbs are non-oracular even when their body is malformed.
    if !is_booking_pack_verb(&verb) {
        return Err(public_booking_not_found());
    }
    let (_, publication) = resolve_public_booking_page(&server, &page_token)?;
    let request = json_payload(payload)?;
    // A configured but unlisted event type is not part of this publication.
    if let BookingOperationRequest::Book(BookingBookInput::Hold(input)) = &request
        && !publication
            .event_types
            .iter()
            .any(|card| card.key == input.event_type)
    {
        return Err(public_booking_not_found());
    }
    let transport = public_http_transport_context(peer)?;
    dispatch_public_booking_verb(&server, &page_token, &verb, request, &transport)
        .await
        .map(Json)
}

/// Called only after the public capability check. The typed match precedes
/// executor dispatch and the executor remains the sole admission call site.
async fn dispatch_public_booking_verb(
    server: &Arc<SyncServer>,
    page_token: &str,
    verb: &str,
    request: BookingOperationRequest,
    transport: &BookingTransportContext,
) -> Result<BookingOperationResponse, ApiError> {
    match_public_booking_verb(verb, &request)?;
    execute_booking_operation(server, page_token, request, transport).await
}

/// Only the listener's peer context supplies the public source IP. Forwarding
/// headers and bearer headers have no role here. Missing context fails closed.
fn public_http_transport_context(
    peer: Result<ConnectInfo<SocketAddr>, axum::extract::rejection::ExtensionRejection>,
) -> Result<BookingTransportContext, ApiError> {
    let ConnectInfo(peer) = peer
        .map_err(|_| ApiError::internal_server_error("public booking peer context unavailable"))?;
    Ok(BookingTransportContext {
        source_ip: peer.ip(),
        authenticated_actor_ref: None,
        transport: BookingTransport::PublicHttp,
    })
}

/// Applies to successes, ApiError refusals, and matched-route extractor errors.
/// No content is followed, downloaded, or interpreted as executable bytes.
async fn public_booking_response(mut response: Response) -> Response {
    let inline_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| matches!(value.trim(), "application/json" | "text/html"));
    if response.status() == StatusCode::NOT_FOUND
        || response.status() == StatusCode::METHOD_NOT_ALLOWED
    {
        response = public_booking_not_found().into_response();
    } else if response.status().is_redirection() || response.headers().contains_key(LOCATION) {
        response =
            ApiError::internal_server_error("public booking response policy refused redirect")
                .into_response();
    } else if !inline_type {
        response = if response.status().is_client_error() {
            ApiError::bad_request("invalid public booking request", None).into_response()
        } else {
            ApiError::internal_server_error("public booking response policy refused content type")
                .into_response()
        };
    }
    // Storage/lifecycle failures must not expose internal subjects or vault
    // details, even if an underlying ApiError has richer diagnostics.
    if response.status().is_server_error() {
        response =
            ApiError::internal_server_error("public booking operation unavailable").into_response();
    }
    response.headers_mut().remove(LOCATION);
    response
        .headers_mut()
        .insert(CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
#[path = "public_fixture.rs"]
mod fixture;
#[cfg(test)]
#[path = "public_lifecycle_tests.rs"]
mod lifecycle_tests;
#[cfg(test)]
#[path = "public_tests.rs"]
mod tests;
