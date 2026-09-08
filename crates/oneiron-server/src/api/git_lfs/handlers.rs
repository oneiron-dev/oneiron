//! LFS batch, upload, download, and verify handlers.

use super::gate::{LfsAccess, authorize, require_lfs_write};
use super::support::{
    LFS_BATCH_NOT_FOUND, LFS_BATCH_UNPROCESSABLE, LFS_OBJECT_MEDIA_TYPE, declared_size, href_base,
    lfs_engine_error, lfs_json_response, now_secs,
};
use super::wire::{
    LfsAction, LfsBatchObject, LfsBatchOperation, LfsBatchRequest, LfsBatchResponse,
    LfsBatchResponseObject, LfsObjectError, LfsUploadResponse, LfsVerifyRequest, LfsVerifyResponse,
};
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::response::Response;
use oneiron::TimeRange;
use oneiron::origin::lfs::LFS_BASIC_TRANSFER;
use oneiron::origin::lfs::LfsOid;
use oneiron::origin::lfs::check_lfs_expectation;
use std::collections::BTreeMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /git/{repo}/info/lfs/objects/batch` — transfer negotiation.
pub(crate) async fn lfs_batch(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    // Read is the floor for reaching the object plane at all; the operation
    // the body names decides whether the write row applies as well.
    let auth = authorize(&headers, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
    let request: LfsBatchRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("lfs batch body is not a batch request", None))?;
    if request.operation == LfsBatchOperation::Upload {
        require_lfs_write(&auth).map_err(EnvelopedApiError::from)?;
    }
    let offers_basic = request
        .transfers
        .iter()
        .any(|transfer| transfer.as_str() == LFS_BASIC_TRANSFER);
    if !request.transfers.is_empty() && !offers_basic {
        return Err(ApiError::bad_request(
            "oneiron origin serves the basic LFS transfer only",
            Some("transfers"),
        )
        .into());
    }

    let base = href_base(&headers);
    let objects = request
        .objects
        .iter()
        .map(|object| batch_entry(&server, &base, &repo, request.operation, object))
        .collect::<Result<Vec<_>, ApiError>>()?;
    lfs_json_response(
        StatusCode::OK,
        &LfsBatchResponse {
            transfer: LFS_BASIC_TRANSFER,
            objects,
        },
    )
}

/// Answers one batch object: an action it can act on, or an honest error.
///
/// A download of an object this vault does not hold produces a per-object error
/// entry and NEVER a fabricated href: handing a client a link to bytes that do
/// not exist turns a clean 404 into a mid-transfer failure.
fn batch_entry(
    server: &SyncServer,
    base: &str,
    repo: &str,
    operation: LfsBatchOperation,
    object: &LfsBatchObject,
) -> Result<LfsBatchResponseObject, ApiError> {
    let mut entry = LfsBatchResponseObject {
        oid: object.oid.clone(),
        size: object.size,
        authenticated: true,
        actions: BTreeMap::new(),
        error: None,
    };
    let Ok(oid) = LfsOid::parse_hex(&object.oid) else {
        entry.error = Some(LfsObjectError {
            code: LFS_BATCH_UNPROCESSABLE,
            message: "oid is not a 64-character sha256",
        });
        return Ok(entry);
    };
    let stored = server
        .vault
        .has_lfs_object(oid, object.size)
        .map_err(|error| lfs_engine_error("lfs object lookup failed", &error))?;
    let href = format!("{base}/git/{repo}/info/lfs/objects/{}", oid.to_hex());
    match operation {
        LfsBatchOperation::Download if stored => {
            entry.actions.insert("download", LfsAction { href });
        }
        LfsBatchOperation::Download => {
            entry.error = Some(LfsObjectError {
                code: LFS_BATCH_NOT_FOUND,
                message: "object is not stored in this vault",
            });
        }
        // An object this vault already holds needs no upload action: the
        // client is told it is done, which is what makes dedup visible on the
        // wire instead of re-sending bytes.
        LfsBatchOperation::Upload if stored => {}
        LfsBatchOperation::Upload => {
            entry.actions.insert(
                "verify",
                LfsAction {
                    href: format!("{href}/verify"),
                },
            );
            entry.actions.insert("upload", LfsAction { href });
        }
    }
    Ok(entry)
}

/// `PUT|POST /git/{repo}/info/lfs/objects/{oid}` — exact body upload.
pub(crate) async fn lfs_upload(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // The negotiated length when the client stated one. Both halves of the
    // expectation run before the engine is called, so a mismatch writes
    // nothing at all rather than writing and then repenting.
    check_lfs_expectation(oid, declared_size(&headers), &body)
        .map_err(|error| lfs_engine_error("lfs upload did not match its declaration", &error))?;
    let now = now_secs()?;
    let outcome = server
        .vault
        .put_lfs_object(
            oid,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .map_err(|error| lfs_engine_error("lfs object store failed", &error))?;
    lfs_json_response(
        StatusCode::OK,
        &LfsUploadResponse {
            oid: outcome.object.oid.to_hex(),
            size: outcome.object.size_bytes,
        },
    )
}

/// `GET /git/{repo}/info/lfs/objects/{oid}` — the stored bytes.
pub(crate) async fn lfs_download(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // Re-checks length and re-hashes the body inside the engine. A corrupt
    // stored body raises here instead of being served as a success.
    let Some(bytes) = server
        .vault
        .get_lfs_object(oid)
        .map_err(|error| lfs_engine_error("lfs object read failed", &error))?
    else {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    };
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, LFS_OBJECT_MEDIA_TYPE)],
        bytes,
    )
        .into_response())
}

/// `POST /git/{repo}/info/lfs/objects/{oid}/verify` — the stored-bytes verdict.
pub(crate) async fn lfs_verify(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, route_oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    let request: LfsVerifyRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("lfs verify body is not {oid, size}", None))?;
    let oid = LfsOid::parse_hex(&request.oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // The route and the body both name an object; a verdict about a THIRD one
    // would be an answer to a question nobody asked.
    if LfsOid::parse_hex(&route_oid).ok() != Some(oid) {
        return Err(ApiError::bad_request(
            "lfs verify body names a different object than its route",
            Some("oid"),
        )
        .into());
    }
    let ok = server
        .vault
        .verify_lfs_object(oid, request.size)
        .map_err(|error| lfs_engine_error("lfs object verification failed", &error))?;
    lfs_json_response(
        StatusCode::OK,
        &LfsVerifyResponse {
            oid: oid.to_hex(),
            size: request.size,
            ok,
        },
    )
}
