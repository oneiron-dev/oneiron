//! LFS batch, upload, download, and verify handlers.

use super::gate::{LfsAccess, authorize_request, require_lfs_write};
use super::support::{
    LFS_BATCH_NOT_FOUND, LFS_BATCH_UNPROCESSABLE, LFS_OBJECT_MEDIA_TYPE, LfsMarkedRead,
    declared_size, href_base, lfs_disk_floor, lfs_engine_error, lfs_json_response, lfs_waited_out,
    now_secs, read_whole,
};
use super::wire::{
    LfsAction, LfsBatchObject, LfsBatchOperation, LfsBatchRequest, LfsBatchResponse,
    LfsBatchResponseObject, LfsObjectError, LfsUploadResponse, LfsVerifyRequest, LfsVerifyResponse,
};
use crate::api::Transfers;
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use crate::wire_telemetry::LimitRow;
use axum::body::{Body, Bytes};
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::response::IntoResponse;
use axum::response::Response;
use oneiron::origin::lfs::LFS_BASIC_TRANSFER;
use oneiron::origin::lfs::LfsOid;
use std::collections::BTreeMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /git/{repo}/info/lfs/objects/batch` — transfer negotiation.
pub(crate) async fn lfs_batch(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    parts: Parts,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    // Read is the floor for reaching the object plane at all; the operation
    // the body names decides whether the write row applies as well.
    let auth =
        authorize_request(&parts, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
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

    let base = href_base(&parts.headers);
    let at = (base.as_str(), repo.as_str());
    let objects = request
        .objects
        .iter()
        .map(|object| batch_entry(&server, &auth, at, request.operation, object))
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
/// not exist turns a clean 404 into a mid-transfer failure. An object is
/// offered as the machine `auth`'s request proved may read it (FIX 4937).
fn batch_entry(
    server: &SyncServer,
    auth: &crate::auth::CoreAuth,
    (base, repo): (&str, &str),
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
    // An object a world withheld from the requesting machine keeps is
    // offered as absent, and so is a lift-marked one to anyone but the owner
    // (FIX 2897): an offer spends and asks nothing.
    let offered = stored
        && !oneiron::sync::chunks::lfs_object_withheld_as(
            &server.vault,
            oid,
            auth.peer(),
            marked_read(server, auth, oid).is_some(),
        )
        .unwrap_or(true);
    let href = format!("{base}/git/{repo}/info/lfs/objects/{}", oid.to_hex());
    match operation {
        LfsBatchOperation::Download if offered => {
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
///
/// The one refusal an upload meets is the disk floor: a declared size that
/// would take the vault's disk below its reserve is refused before a byte is
/// spooled, and an upload that gets there while it streams is ended. The
/// per-object size and the storage quota are rows: an upload past either
/// still lands, and the row asks whether everything is okay. Past the bound
/// on transfers the upload waits its turn. Its worker holds the transfer
/// permit, its disk claim and its quota reservation until it ends, and from
/// the end of its body its room in memory for the install.
pub(crate) async fn lfs_upload(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, oid)): Path<(String, String)>,
    parts: Parts,
    body: Body,
) -> Result<Response, EnvelopedApiError> {
    let auth =
        authorize_request(&parts, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    let size_row = server.config.max_lfs_object_bytes;
    let declared = declared_size(&parts.headers);
    if let Some(size) = declared.filter(|size| *size > size_row) {
        server
            .transfers
            .questions
            .ask(LimitRow::LfsObjectSize, size_row, size);
    }
    // A declared upload writes its spool and then its stored copy.
    let floor = server.transfers.disk.clone();
    let page = server.transfers.lfs_page();
    let room = |size: u64| size.saturating_add(super::streaming::stored_copy(size, page));
    if let Some(size) = declared
        && !floor.has_room_for(room(size))
    {
        return Ok(lfs_disk_floor());
    }
    let Ok(permit) = server.transfers.admit_lfs(auth.principal_ref()).await else {
        return Ok(lfs_waited_out());
    };
    // The quota reads every stored object, so it runs in the blocking pool
    // under the permit just taken: at most as many reads as transfers, and
    // none on the runtime.
    let reserving = Arc::clone(&server);
    let (reserved, permit) = crate::api::transfer::spawn_worker(move || {
        let size = declared.unwrap_or(size_row);
        let reserved = reserving.transfers.reserve_lfs(&reserving.vault, size);
        (reserved, permit)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs quota worker failed"))?;
    let reservation =
        reserved.map_err(|error| lfs_engine_error("lfs quota could not be read", &error))?;
    // Claimed at its turn, still before a byte is read: the room this upload
    // will write is room no other upload counts as free.
    let claim = floor.claim();
    if let Some(size) = declared
        && !floor.hold(&claim, room(size))
    {
        return Ok(lfs_disk_floor());
    }
    let outcome = super::streaming::upload(
        Arc::clone(&server.vault),
        super::streaming::UploadTerms {
            oid,
            declared,
            size_row,
            floor,
            page,
            reservation,
            installs: server.transfers.lfs_installs(),
            wait: server.transfers.wait,
            questions: Arc::clone(&server.transfers.questions),
            now: now_secs()?,
            idle: server.transfers.idle,
        },
        body,
        (permit, claim),
    )
    .await?;
    let outcome = match outcome {
        super::streaming::Uploaded::Stored(outcome) => outcome,
        super::streaming::Uploaded::Floored => return Ok(lfs_disk_floor()),
        super::streaming::Uploaded::WaitedOut => return Ok(lfs_waited_out()),
    };
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
    parts: Parts,
) -> Result<Response, EnvelopedApiError> {
    let auth =
        authorize_request(&parts, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    let Some(record) = server
        .vault
        .lfs_object(oid)
        .map_err(|error| lfs_engine_error("lfs object lookup failed", &error))?
    else {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    };
    // The machine the request's connection proved: the preflight and every
    // piece are judged for it (FIX 4937). A lift-marked object goes to the
    // owner this request verified, his read judged again for every piece
    // (FIX 2897).
    let peer = auth.peer();
    let read = marked_read(&server, &auth, oid);
    if oneiron::sync::chunks::lfs_object_withheld_as(&server.vault, oid, peer, read.is_some())
        .unwrap_or(true)
    {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    }
    // Preflight in the blocking pool preserves the old fail-before-200 contract
    // without ever buffering the object. The stream verifies each chunk again;
    // a deletion/corruption racing preflight terminates the HTTP body with error.
    //
    // Its room in memory, then one permit, cover the preflight and the
    // stream: each worker holds them in turn, so a client that hangs up
    // mid-preflight frees nothing early.
    let Some(room) = Transfers::read_room(&server.vault, oid)
        .map_err(|error| lfs_engine_error("lfs object lookup failed", &error))?
    else {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    };
    let Some(room) = server.transfers.lfs_read_room(room).await else {
        return Ok(lfs_waited_out());
    };
    let Ok(permit) = server.transfers.admit_lfs(auth.principal_ref()).await else {
        return Ok(lfs_waited_out());
    };
    let vault = Arc::clone(&server.vault);
    let (verified, hold) = crate::api::transfer::spawn_worker(move || {
        (
            vault.verify_lfs_object(oid, record.size_bytes),
            (room, permit),
        )
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs verify worker failed"))?;
    let verified = verified.map_err(|error| lfs_engine_error("lfs object read failed", &error))?;
    if !verified {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    }
    let mut response = super::streaming::download(
        Arc::clone(&server.vault),
        (oid, peer, read),
        hold,
        server.transfers.idle,
    )
    .into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        LFS_OBJECT_MEDIA_TYPE.parse().expect("static media type"),
    );
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, record.size_bytes.into());
    Ok(response)
}

/// The owner's read of the lift-marked object `oid`, as `auth` verified him
/// (FIX 2897): `None` for an unmarked object, which reads exactly as before,
/// and for any other caller. A basic transfer carries no why, so it builds
/// no agent's read.
fn marked_read(
    server: &SyncServer,
    auth: &crate::auth::CoreAuth,
    oid: LfsOid,
) -> Option<LfsMarkedRead> {
    if !server.vault.lfs_object_secret_withheld(oid).unwrap_or(true) {
        return None;
    }
    LfsMarkedRead::of(&server.vault, auth, oid, None)
}

/// A verify body is one `{oid, size}`; this is room for it many times over.
const VERIFY_BODY_BYTES: usize = 64 * 1024;

/// `POST /git/{repo}/info/lfs/objects/{oid}/verify` — the stored-bytes verdict.
pub(crate) async fn lfs_verify(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, route_oid)): Path<(String, String)>,
    parts: Parts,
    body: Body,
) -> Result<Response, EnvelopedApiError> {
    let auth =
        authorize_request(&parts, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    // It waits on its headers and reads its body at its turn, so a request
    // in line holds none of it. Its room in memory is its route's object's,
    // the only one it may read, sized before it waits.
    let sized = match LfsOid::parse_hex(&route_oid) {
        Ok(oid) => Transfers::read_room(&server.vault, oid)
            .map_err(|error| lfs_engine_error("lfs object lookup failed", &error))?,
        Err(_) => None,
    };
    let Some(room) = server
        .transfers
        .lfs_read_room(sized.unwrap_or(crate::api::transfer::READ_ROOM))
        .await
    else {
        return Ok(lfs_waited_out());
    };
    let Ok(permit) = server.transfers.admit_lfs(auth.principal_ref()).await else {
        return Ok(lfs_waited_out());
    };
    let body = read_whole(body, VERIFY_BODY_BYTES).await?;
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
    // An object that was not stored when the verify took its room is not
    // read, even if it has landed since: its manifest is room the verify
    // does not hold.
    if sized.is_none() {
        return lfs_json_response(
            StatusCode::OK,
            &LfsVerifyResponse {
                oid: oid.to_hex(),
                size: request.size,
                ok: false,
            },
        );
    }
    let vault = Arc::clone(&server.vault);
    let size = request.size;
    let ok = crate::api::transfer::spawn_worker(move || {
        let _hold = (room, permit);
        vault.verify_lfs_object(oid, size)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs verify worker failed"))?
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
