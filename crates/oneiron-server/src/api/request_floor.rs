//! The API's request floor (`limits.request_body_bytes`, ABC transport rows
//! T1, T3, T4). Every route that reads its body whole and sets no bound of
//! its own reads up to the row. A body that declares more than the row is
//! refused in the typed envelope, which names the row; axum's own refusal is
//! plain text and names nothing.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// The row's config key, named in the refusal.
const ROW_KEY: &str = "limits.request_body_bytes";

/// The field a refusal names: the request body as a whole.
const BODY_FIELD: &str = "body";

/// The row, as an extractor body limit.
pub(super) fn request_floor(server: &SyncServer) -> usize {
    usize::try_from(server.config.limits.request_body_bytes).unwrap_or(usize::MAX)
}

/// The layer every API route reads its body under, unless its own layer
/// (the facade nest, e-sign, the webhooks) sets another.
pub(super) fn request_floor_layer(server: &SyncServer) -> DefaultBodyLimit {
    DefaultBodyLimit::max(request_floor(server))
}

/// Names the row in a refusal it caused. An extractor's 413 that is not
/// already a typed envelope, for a body whose `Content-Length` passed the
/// row, becomes the typed `PAYLOAD_TOO_LARGE` naming the row, the bound and
/// the bytes declared. Any other response, a route's own typed 413 and a 413
/// of a smaller route bound included, passes as it is.
pub(super) async fn name_request_floor(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let response = next.run(request).await;
    let floor = server.config.limits.request_body_bytes;
    let Some(declared) = declared.filter(|declared| *declared > floor) else {
        return response;
    };
    let typed = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE || typed {
        return response;
    }
    let max_bytes = usize::try_from(floor).unwrap_or(usize::MAX);
    ApiError::new(
        format!("the request body exceeds {ROW_KEY} ({floor} bytes)"),
        ApiErrorDetails::PayloadTooLarge {
            field: BODY_FIELD.to_owned(),
            max_bytes,
            received_bytes: usize::try_from(declared).unwrap_or(usize::MAX),
        },
        [format!(
            "Send a request body of at most {floor} bytes, or raise {ROW_KEY} on this server."
        )],
    )
    .into_response()
}
