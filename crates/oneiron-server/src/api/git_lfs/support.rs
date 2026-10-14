//! LFS size, href, time, and JSON helpers.

use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use axum::http::header::RETRY_AFTER;
use axum::response::IntoResponse;
use axum::response::Response;
use oneiron::ErrorKind;
use oneiron::Vault;
use oneiron::origin::lfs::LFS_JSON_MEDIA_TYPE;
use oneiron::origin::lfs::LfsOid;
use serde::Serialize;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Whether a device-only world keeps `oid` from leaving, judged in the
/// blocking pool: the judge takes the privacy lock and reads the vault, which
/// a streaming body must never do on a runtime worker. A judge that cannot
/// answer refuses.
pub(super) async fn lfs_object_withheld_now(vault: &Arc<Vault>, oid: LfsOid) -> bool {
    let vault = Arc::clone(vault);
    tokio::task::spawn_blocking(move || {
        oneiron::sync::chunks::lfs_object_withheld(&vault, oid).unwrap_or(true)
    })
    .await
    .unwrap_or(true)
}

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

/// A transfer refused before it began, in the LFS error shape; a 503 says
/// when to come back.
pub(super) fn lfs_refusal(status: StatusCode, message: &'static str) -> Response {
    let body = serde_json::json!({ "message": message }).to_string();
    let mut response = (status, [(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)], body).into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

/// Every LFS transfer permit is held: refused now, never queued.
pub(super) fn lfs_saturated() -> Response {
    lfs_refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        "lfs transfers are at their limit; retry later",
    )
}

pub(super) fn lfs_json_response(
    status: StatusCode,
    body: &impl Serialize,
) -> Result<Response, EnvelopedApiError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|_| ApiError::internal_server_error("lfs response could not be serialized"))?;
    Ok((status, [(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)], encoded).into_response())
}
