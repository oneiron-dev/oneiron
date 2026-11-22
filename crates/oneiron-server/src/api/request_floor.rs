//! The API's request floor (`limits.request_body_bytes`, ABC transport rows
//! T1, T3, T4). Every route that reads its body whole and sets no bound of
//! its own reads up to the row. A body that declares more than the row, or
//! that declares nothing and reads past it, is refused in the typed envelope,
//! which names the row; axum's own refusal is plain text and names nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt as _;

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
/// already a typed envelope becomes the typed `PAYLOAD_TOO_LARGE` naming the
/// row, the bound and the bytes: those declared, or, for a body that declared
/// no length (a chunked body), those that arrived, counted as they were read.
/// A body that declared within the row, an undeclared body that stopped
/// within it (a smaller route bound refused it), a route's own typed 413 and
/// any other response pass as they are.
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
    // A body that declares no length is counted as it is read, so its 413
    // is named the row's only when what arrived passed the row.
    let arrived = Arc::new(AtomicU64::new(0));
    let request = if declared.is_none() {
        let counter = Arc::clone(&arrived);
        request.map(|body| {
            Body::from_stream(body.into_data_stream().map(move |piece| {
                if let Ok(piece) = &piece {
                    counter.fetch_add(piece.len() as u64, Ordering::Relaxed);
                }
                piece
            }))
        })
    } else {
        request
    };
    let response = next.run(request).await;
    let floor = server.config.limits.request_body_bytes;
    let max_bytes = usize::try_from(floor).unwrap_or(usize::MAX);
    let received = match declared {
        Some(declared) => declared,
        None => arrived.load(Ordering::Relaxed),
    };
    if received <= floor {
        return response;
    }
    let received_bytes = usize::try_from(received).unwrap_or(usize::MAX);
    let typed = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if response.status() != StatusCode::PAYLOAD_TOO_LARGE || typed {
        return response;
    }
    ApiError::new(
        format!("the request body exceeds {ROW_KEY} ({floor} bytes)"),
        ApiErrorDetails::PayloadTooLarge {
            field: BODY_FIELD.to_owned(),
            max_bytes,
            received_bytes,
        },
        [format!(
            "Send a request body of at most {floor} bytes, or raise {ROW_KEY} on this server."
        )],
    )
    .into_response()
}
