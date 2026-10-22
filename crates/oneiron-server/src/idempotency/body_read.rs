//! A keyed request's body, read up to the keyed routes' limit, and why it could not be read.
//! `keyed_body` is its call surface (FIX 9528).
//! `crate::error::ApiError` defines the typed refusal forwarded here.

use std::error::Error as _;

use axum::body::{Body, Bytes, HttpBody as _};
use axum::http::HeaderMap;
use futures_util::StreamExt as _;

use super::ApiError;
use crate::error::ApiErrorDetails;

/// The field a body refusal names: the request body as a whole.
const BODY_FIELD: &str = "body";

/// `body`, whole, when it fits `limit`, the limit the keyed routes read up
/// to. Otherwise the typed refusal its route's envelope carries: a body past
/// the limit is `PAYLOAD_TOO_LARGE` naming that limit and the bytes it
/// declared or had sent when it passed it, and a body that stalled past the
/// server's idle limit or broke off is a `BAD_REQUEST` naming the body and
/// the cause. No limit or deadline is added here: the limit is the one the
/// layer already read up to, and a stall is the connection's own idle limit
/// (`limits.body_idle_timeout_ms`).
pub(super) async fn keyed_body(
    body: Body,
    headers: &HeaderMap,
    limit: usize,
) -> Result<Bytes, ApiError> {
    let declared = body.size_hint().lower();
    if usize::try_from(declared).map_or(true, |declared| declared > limit) {
        return Err(too_large(headers, limit, declared));
    }
    let mut read = Vec::new();
    let mut frames = body.into_data_stream();
    while let Some(frame) = frames.next().await {
        let frame = frame.map_err(|error| unreadable(&error))?;
        if frame.len() > limit - read.len() {
            let sent = read.len().saturating_add(frame.len());
            return Err(too_large(
                headers,
                limit,
                u64::try_from(sent).unwrap_or(u64::MAX),
            ));
        }
        read.extend_from_slice(&frame);
    }
    Ok(Bytes::from(read))
}

/// A body past `limit`: the bytes its `Content-Length` declared, else the
/// bytes it had sent when it passed the limit (`sent`).
fn too_large(headers: &HeaderMap, limit: usize, sent: u64) -> ApiError {
    let declared = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let received = declared.unwrap_or(sent);
    tracing::warn!(
        reason = "body_too_large",
        limit,
        received,
        "keyed request body is past the keyed routes' limit"
    );
    ApiError::new(
        format!("the request body exceeds the {limit} byte limit a keyed request is read up to"),
        ApiErrorDetails::PayloadTooLarge {
            field: BODY_FIELD.to_owned(),
            max_bytes: limit,
            received_bytes: usize::try_from(received).unwrap_or(usize::MAX),
        },
        [format!("Send a request body of at most {limit} bytes.")],
    )
}

/// A body that could not be read: one that stalled past the connection's
/// idle limit, or one that broke off.
fn unreadable(error: &axum::Error) -> ApiError {
    if stalled(error) {
        tracing::warn!(reason = "body_stalled", "keyed request body stalled");
        return ApiError::new(
            "the request body stalled past the server's body idle limit (limits.body_idle_timeout_ms)",
            ApiErrorDetails::BadRequest {
                field: Some(BODY_FIELD.to_owned()),
            },
            ["Send the request body without pausing, then retry."],
        );
    }
    tracing::warn!(reason = "body_read_failed", %error, "failed to read keyed request body");
    ApiError::new(
        format!("the request body could not be read: {error}"),
        ApiErrorDetails::BadRequest {
            field: Some(BODY_FIELD.to_owned()),
        },
        ["Send the whole request body again."],
    )
}

/// Whether `error` is the connection's idle limit cutting a stalled body.
fn stalled(error: &axum::Error) -> bool {
    let mut cause = error.source();
    while let Some(error) = cause {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            return true;
        }
        cause = error.source();
    }
    false
}
