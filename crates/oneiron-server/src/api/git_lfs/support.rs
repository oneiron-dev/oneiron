//! LFS size, href, time, and JSON helpers.

use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use axum::response::IntoResponse;
use axum::response::Response;
use oneiron::ErrorKind;
use oneiron::origin::lfs::LFS_JSON_MEDIA_TYPE;
use serde::Serialize;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The largest LFS object body this origin accepts, per route.
///
/// A named constant rather than configuration on purpose: axum's default body
/// limit is 2 MiB, which would cap LFS uploads far below anything LFS is FOR,
/// and a silent cap is worse than a stated one. 16 MiB is the v1 default;
/// moving it wants a product reason, not a deployment knob.
pub(crate) const LFS_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// The media type a downloaded object body carries. LFS bytes are opaque: this
/// origin never guesses a content type for content it stores as a digest.
pub(super) const LFS_OBJECT_MEDIA_TYPE: &str = "application/octet-stream";

/// Per-object failure codes the batch response speaks (Git-LFS batch API).
pub(super) const LFS_BATCH_NOT_FOUND: u16 = 404;

pub(super) const LFS_BATCH_UNPROCESSABLE: u16 = 422;

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/// Maps an engine failure onto the wire without laundering it.
///
/// A declaration mismatch is the CLIENT's fault and says so; everything else —
/// corruption of a stored body included — is this origin's fault and is never
/// reported as a bad request, because a client cannot fix it by retrying with
/// different bytes.
pub(super) fn lfs_engine_error(message: &'static str, error: &oneiron::Error) -> ApiError {
    match error.kind() {
        ErrorKind::InvalidLfsObject => ApiError::bad_request(error.to_string(), Some("oid")),
        _ => ApiError::internal_server_error(message),
    }
}

/// The length the client declared for this body, when it declared one.
pub(super) fn declared_size(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

/// The absolute origin an action href is built from.
///
/// A stock LFS client follows absolute hrefs, so one is minted from the host
/// the request arrived at rather than from configuration this ticket does not
/// own. A request with no usable `Host` gets root-relative hrefs, which is the
/// honest answer: the origin cannot invent a hostname it was never told.
pub(super) fn href_base(headers: &HeaderMap) -> String {
    let Some(host) = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
    else {
        return String::new();
    };
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|scheme| *scheme == "https")
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

pub(super) fn now_secs() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ApiError::internal_server_error("system clock precedes the unix epoch"))
}

pub(super) fn lfs_json_response(
    status: StatusCode,
    body: &impl Serialize,
) -> Result<Response, EnvelopedApiError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|_| ApiError::internal_server_error("lfs response could not be serialized"))?;
    Ok((status, [(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)], encoded).into_response())
}
