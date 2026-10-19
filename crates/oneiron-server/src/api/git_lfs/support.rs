//! LFS size, href, time, and JSON helpers.

use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use axum::body::Body;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use axum::http::header::RETRY_AFTER;
use axum::response::IntoResponse;
use axum::response::Response;
use futures_util::StreamExt;
use oneiron::ErrorKind;
use oneiron::origin::lfs::LFS_JSON_MEDIA_TYPE;
use serde::Serialize;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Why the next piece of `oid` stays on this device for the machine `peer`
/// (FIX 4937, 4939): the body's error, naming the hold's content-free
/// reason; a check that cannot be read is an integrity hold. `None` while the
/// piece may go.
pub(super) fn lfs_piece_hold(
    vault: &oneiron::Vault,
    oid: oneiron::origin::lfs::LfsOid,
    peer: oneiron::authority::PeerMachine,
) -> Option<std::io::Error> {
    let reason = match oneiron::sync::chunks::lfs_object_hold_for(vault, oid, peer) {
        Ok(None) => return None,
        Ok(Some(hold)) => hold.reason(),
        Err(_) => oneiron::settings::ReleaseHold::Placement.reason(),
    };
    Some(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("lfs object kept on this device: {reason}"),
    ))
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

/// The transfer waited its whole deadline for its turn. Nothing was started.
pub(super) fn lfs_waited_out() -> Response {
    lfs_refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        "lfs transfer waited past limits.queue_wait_timeout_ms for its turn; nothing was started; retry",
    )
}

/// A request body read whole, at most `limit` bytes. A request that waits
/// for a transfer permit reads its body only at its turn, so one in line
/// holds none of it; the listener ends a body that pauses past its idle
/// limit. The buffer grows by doubling but never past `limit`, so what the
/// memory row counts for it holds.
pub(super) async fn read_whole(body: Body, limit: usize) -> Result<Vec<u8>, ApiError> {
    let mut pieces = body.into_data_stream();
    let mut whole = Vec::new();
    while let Some(piece) = pieces.next().await {
        let piece = piece.map_err(|_| {
            ApiError::bad_request("the request body ended before it was whole", None)
        })?;
        let length = whole.len().saturating_add(piece.len());
        if length > limit {
            return Err(ApiError::payload_too_large("body", limit, length));
        }
        if length > whole.capacity() {
            let grown = length.max(whole.capacity().saturating_mul(2)).min(limit);
            whole.reserve_exact(grown - whole.len());
        }
        whole.extend_from_slice(&piece);
    }
    Ok(whole)
}

/// The upload would take the vault's disk below its reserve: the disk
/// floor, the one refusal an upload meets.
pub(super) fn lfs_disk_floor() -> Response {
    lfs_refusal(
        StatusCode::INSUFFICIENT_STORAGE,
        "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes); nothing was stored",
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
