//! The artifact write routes' bodies, streamed (FIX 22074). `POST
//! /v1/core/artifacts`, `.../{artifact}/versions` and `.../{artifact}/outputs`
//! read their body onto an anonymous file the vault stages (`api::body_spool`)
//! and decode its `content_base64` member from there into a file of its own
//! as the spool is read, never one string in memory; every other member is
//! the route's closed head, read as its DTO read it. The route's 96 MiB bound
//! is the request body's, counted as it arrives whether or not a length is
//! declared. Both files are gone once dropped.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::HeaderMap;
use serde::de::DeserializeOwned;

use crate::api::body_spool::{
    self, Base64FileSink, BulkMember, HeadFail, SinkRefusal, SpoolPolicy, SpooledField,
    TextFileSink, Unspooled,
};
use crate::error::ApiError;
use crate::server::SyncServer;

/// The member that carries the file, as standard base64.
const CONTENT_MEMBER: &str = "content_base64";

/// A write route's body, decoded: every member but the content as `H`, and
/// the content's bytes in a file of their own.
pub(super) struct StreamedBody<H> {
    pub(super) head: H,
    pub(super) content: SpooledField,
}

/// Reads `body`, at most `limit` bytes of it, onto a spool on a transfer
/// worker and decodes it there: the content member to its own file, the
/// rest as `H`. A body past `limit`, declared or counted, is refused as too
/// large before or as it arrives; a body that is not one JSON object with
/// exactly one string content member, or whose head is not `H`, is invalid
/// JSON, as the route's JSON reader refused it; content that is not standard
/// base64 is refused as the route refused it.
pub(super) async fn read<H: DeserializeOwned + Send + 'static>(
    server: &SyncServer,
    headers: &HeaderMap,
    body: Body,
    limit: u64,
) -> Result<StreamedBody<H>, ApiError> {
    // A body that does not say it is JSON is refused as the route's JSON
    // reader refused it.
    if !crate::api::has_json_content_type(headers) {
        return Err(body_spool::invalid_json());
    }
    let declared = body_spool::declared_length(headers);
    if let Some(declared) = declared.filter(|declared| *declared > limit) {
        return Err(too_large(limit, declared));
    }
    let over = Arc::new(AtomicBool::new(false));
    let body = body_spool::capped(body, limit, Arc::clone(&over));
    let vault = Arc::clone(&server.vault);
    let read = body_spool::spool_then(
        server,
        declared,
        body,
        SpoolPolicy::default(),
        move |mut spool| {
            let file = vault
                .archive_spool_file()
                .map_err(|error| body_spool::create_failed(error).refusal())?;
            let head_file = vault
                .archive_spool_file()
                .map_err(|error| body_spool::create_failed(error).refusal())?;
            let (syntax, head, content) = {
                let mut memory = spool
                    .admit_sealed_decode_buffers()
                    .map_err(body_spool::sealed_decode_memory_refused)?;
                let mut content = Base64FileSink::new_admitted(file, &mut memory);
                let mut head = TextFileSink::new_admitted(head_file, &mut memory);
                let syntax = spool.object_head_admitted(
                    &mut [BulkMember::required(CONTENT_MEMBER, &mut content)],
                    &mut head,
                    &mut memory,
                );
                (syntax, head.into_field(), content.into_field())
            };
            // No working buffer or lease survives into the next admission.
            syntax.map_err(|error| match error {
                HeadFail::Invalid => body_spool::invalid_json(),
                HeadFail::Failed => Unspooled::Failed.refusal(),
            })?;
            let head = {
                let head_file = head.map_err(Unspooled::refusal)?;
                let mut memory = spool
                    .admit_reader()
                    .map_err(body_spool::sealed_decode_memory_refused)?;
                head_file.json_admitted::<H>(&mut memory).map_err(|error| {
                    if error.is_io() {
                        Unspooled::Failed.refusal()
                    } else {
                        body_spool::invalid_json()
                    }
                })?
            };
            Ok::<_, ApiError>((head, content))
        },
    )
    .await;
    if over.load(Ordering::Relaxed) {
        return Err(too_large(limit, limit.saturating_add(1)));
    }
    let (head, content) = read.map_err(Unspooled::refusal)??;
    match content {
        Ok(content) => Ok(StreamedBody { head, content }),
        Err(SinkRefusal::NotBase64) => Err(ApiError::bad_request(
            "content must be base64",
            Some(CONTENT_MEMBER),
        )),
        Err(SinkRefusal::NoRoom) => Err(Unspooled::NoRoom.refusal()),
        Err(SinkRefusal::Failed) => Err(Unspooled::Failed.refusal()),
    }
}

/// A body past the route's bound.
fn too_large(limit: u64, received: u64) -> ApiError {
    ApiError::payload_too_large(
        "request body",
        usize::try_from(limit).unwrap_or(usize::MAX),
        usize::try_from(received).unwrap_or(usize::MAX),
    )
}
