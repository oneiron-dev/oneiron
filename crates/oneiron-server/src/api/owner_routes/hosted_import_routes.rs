//! `/v1/owner/imports/hosted`: a ChatGPT or Claude.ai export uploaded to the
//! vault's own hostname (ARCH-0027:151 #hosted-import: "Upload bytes go
//! straight to the vault's own hostname"), behind the same owner door as
//! every other owner route. The routes stage the export through the writer
//! `oneiron import <source> <file> --hosted` uses
//! (`commands::hosted_import`), and the vault's hosted-import worker lands
//! it as a job from there (`vault.imports.get` reads its progress).
//!
//! The upload declares the export's source and size first, then sends the
//! export in parts, each a `PUT` at `offset`, the bytes written so far.
//! The upload's state between two parts is its staging folder alone, so a
//! client resumes after a restart of either side at the offset `GET`
//! answers. A part that does not start at the upload's offset, or runs past
//! the declared size, writes nothing. The part that reaches the declared
//! size stages the export: there is no separate completion. The vault's
//! disk floor (`limits.disk_reserve_bytes`, the floor every upload keeps) is
//! the cap: a declared size it has no room for is refused before a byte is
//! sent, and each part claims its bytes on it as it spools.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post, put};
use oneiron::ingest::history::{HistorySource, HostedImportId};
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::{self, OwnerJsonBody, SpoolPolicy, Unspooled};
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::commands::hosted_import::{self, HostedUpload, UploadRefusal};
use crate::error::{ApiError, ApiErrorDetails};
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// The state a staged upload's refusal names.
const STAGED_STATE: &str = "upload_staged";
/// The state a part at another offset is refused with.
const OFFSET_STATE: &str = "upload_offset";
/// The state a part sent while another is written is refused with.
const BUSY_STATE: &str = "upload_in_progress";

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/imports/hosted",
                summary: "Declares an upload of a ChatGPT or Claude export, its source and its size in bytes, and answers the import's id.",
                row: None,
                shape: None,
            },
            post(declare),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/imports/hosted/{import}/upload",
                summary: "An upload's state: the bytes written so far, which is where its next part starts, and whether its export is staged.",
                row: None,
                shape: None,
            },
            get(state),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/imports/hosted/{import}/upload",
                summary: "Appends a part of the export, its raw bytes, at `offset`; the part that reaches the declared size stages the export for the vault to import.",
                row: None,
                shape: None,
            },
            put(upload),
        ),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclareUpload {
    /// The export's source: `chatgpt` or `claude`.
    source: String,
    /// The export's size in bytes: what its parts add up to.
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadAt {
    /// Where the part starts: the bytes the upload has written so far.
    offset: u64,
}

/// `POST /v1/owner/imports/hosted`: declares an upload, its source and its
/// size, and answers the import's id. Nothing is read yet.
async fn declare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DeclareUpload>,
) -> OwnerReply<HostedUpload> {
    owner(&auth, &server)?;
    let DeclareUpload { source, bytes } = payload.read(&server).await?;
    let source = HistorySource::parse(&source)
        .filter(|source| hosted_import::takes_source(*source))
        .ok_or_else(|| ApiError::bad_request("source must be chatgpt or claude", Some("source")))?;
    if bytes == 0 {
        return Err(
            ApiError::bad_request("an export of no bytes is not an export", Some("bytes")).into(),
        );
    }
    // The floor every upload keeps on the vault's disk, past what uploads in
    // flight have claimed: an export it has no room for is refused before a
    // byte of it is sent.
    if !server.transfers.disk.has_room_for(bytes) {
        return Err(no_room().into());
    }
    let vault_path = server.vault().path().to_path_buf();
    let declared = blocking(move || {
        hosted_import::declare_upload(&vault_path, source, bytes).map_err(OwnerError::Host)
    })
    .await?;
    Ok(Json(declared))
}

/// `GET /v1/owner/imports/hosted/{import}/upload`: the upload's state.
async fn state(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(import): UrlPath<String>,
) -> OwnerReply<HostedUpload> {
    owner(&auth, &server)?;
    let id = import_id(&import)?;
    let vault_path = server.vault().path().to_path_buf();
    let state = blocking(move || Ok(hosted_import::upload_state(&vault_path, id)))
        .await?
        .map_err(|refusal| refused(refusal, &import))?;
    Ok(Json(state))
}

/// `PUT /v1/owner/imports/hosted/{import}/upload?offset=N`: appends the
/// body, the export's next raw bytes, at `offset`. The upload is judged
/// before the body is read, then again as its part is written: a part that
/// starts elsewhere, or runs past the declared size, declared or counted,
/// writes nothing.
async fn upload(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(import): UrlPath<String>,
    query: Result<Query<UploadAt>, QueryRejection>,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<HostedUpload> {
    owner(&auth, &server)?;
    let id = import_id(&import)?;
    let UploadAt { offset } = query_params(query)?;
    let vault_path = server.vault().path().to_path_buf();
    let known = {
        let vault_path = vault_path.clone();
        blocking(move || Ok(hosted_import::upload_state(&vault_path, id)))
            .await?
            .map_err(|refusal| refused(refusal, &import))?
    };
    if known.staged && offset != known.declared_bytes {
        return Err(refused(UploadRefusal::Staged, &import).into());
    }
    if !known.staged && offset != known.offset {
        return Err(refused(UploadRefusal::Offset(known.offset), &import).into());
    }
    let room = known.declared_bytes.saturating_sub(known.offset);
    let declared = body_spool::declared_length(&headers);
    if let Some(length) = declared.filter(|length| *length > room) {
        return Err(past(&known, &import, room, length).into());
    }
    let over = Arc::new(AtomicBool::new(false));
    let body = body_spool::capped(body, room, Arc::clone(&over));
    let written = body_spool::spool_then(
        &server,
        declared,
        body,
        SpoolPolicy::custody(&server),
        move |mut spool| {
            let mut memory = spool
                .admit_reader()
                .map_err(body_spool::reader_memory_refused)?;
            Ok::<_, ApiError>(spool.with_reader_admitted(&mut memory, |part| {
                hosted_import::upload_part(&vault_path, id, offset, part)
            }))
        },
    )
    .await;
    if over.load(Ordering::Relaxed) {
        return Err(past(&known, &import, room, room.saturating_add(1)).into());
    }
    let state = written
        .map_err(Unspooled::refusal)??
        .map_err(|refusal| refused(refusal, &import))?;
    Ok(Json(state))
}

/// The import's id from its path; one that is no id names no upload.
fn import_id(import: &str) -> Result<HostedImportId, ApiError> {
    HostedImportId::parse(import)
        .ok_or_else(|| ApiError::not_found("hosted import upload", Some(import)))
}

/// What an upload's refusal answers.
fn refused(refusal: UploadRefusal, import: &str) -> ApiError {
    match refusal {
        UploadRefusal::NotFound => ApiError::not_found("hosted import upload", Some(import)),
        UploadRefusal::Staged => ApiError::new(
            "this upload's export is staged: it takes no more bytes",
            ApiErrorDetails::InvalidState {
                state: Some(STAGED_STATE.to_owned()),
            },
            ["Read the import's progress with vault.imports.get."],
        ),
        UploadRefusal::Offset(offset) => ApiError::new(
            format!(
                "this upload has written {offset} bytes: its next part starts at offset {offset}"
            ),
            ApiErrorDetails::InvalidState {
                state: Some(OFFSET_STATE.to_owned()),
            },
            [format!("Send the next part with offset={offset}.")],
        ),
        UploadRefusal::Busy => ApiError::new(
            "another part of this upload is being written",
            ApiErrorDetails::InvalidState {
                state: Some(BUSY_STATE.to_owned()),
            },
            ["Wait for that part to end, read the upload's offset, then send the next part."],
        ),
        UploadRefusal::PastDeclared(room) => past_declared(room, room.saturating_add(1)),
        UploadRefusal::NoRoom => no_room(),
        UploadRefusal::Failed(error) => {
            tracing::warn!(import, error = %format!("{error:#}"), "hosted import upload failed");
            ApiError::internal_server_error("the upload's part was not written")
        }
    }
}

/// A part of more bytes than the upload has still to come: past the
/// declared size, or any byte once the export is staged.
fn past(known: &HostedUpload, import: &str, room: u64, received: u64) -> ApiError {
    if known.staged {
        refused(UploadRefusal::Staged, import)
    } else {
        past_declared(room, received)
    }
}

/// A part past the bytes the upload still has to come.
fn past_declared(room: u64, received: u64) -> ApiError {
    ApiError::payload_too_large(
        "upload part",
        usize::try_from(room).unwrap_or(usize::MAX),
        usize::try_from(received).unwrap_or(usize::MAX),
    )
}

/// The vault's disk has no room past its floor for the export.
fn no_room() -> ApiError {
    body_spool::no_room(
        "the vault's disk has no room for this export: nothing was written",
        "Free room on the vault's disk, then upload the export again.",
    )
}
