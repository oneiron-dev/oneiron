//! The sealed custody change's body, spooled and decoded (FIX 5674, FIX 7917,
//! Rule 5). `POST /v1/owner/secrets/custody` reads its body after the owner
//! door, whatever its length, onto an anonymous file the vault stages
//! (`api::body_spool`), under the server's one disk floor (`transfers.disk`,
//! kept at `limits.disk_reserve_bytes`), as the signing doors spool theirs.
//! A surface's frame of numbered envelopes (FIX 5521) is read as one envelope
//! is. That floor or a disk write that runs out of room answers capacity
//! (`disk_capacity`); body size never refuses it (CALLS OWNER_CUSTODY_BODY_SPOOL).
//! The raw spool buffer also uses the process memory line, whose allocation
//! failure is not a disk failure. The sealed input is decoded from
//! its base64 into a file of its own as the spool is read, never one string
//! in memory. The body is ciphertext sealed to the holder, and both files
//! are gone once dropped. It carries no carrier key (FIX 7402): while the
//! carrier wire is on, the engine's recorder seals the input under a key it
//! mints, and the relayed input names that key's reference for the holder.

use std::sync::Arc;

use axum::body::Body;
use axum::http::HeaderMap;
use serde::de::DeserializeOwned;

use crate::api::body_spool::{
    self, Base64FileSink, BulkMember, HeadFail, SinkRefusal, SpoolPolicy, SpooledField,
    TextFileSink, Unspooled,
};
use crate::error::ApiError;
use crate::machine::DiskClaim;
use crate::server::SyncServer;

/// The member that carries the sealed input, as standard base64.
const INPUT_MEMBER: &str = "input_base64";

/// What a change the vault's disk had no room for says.
const NO_ROOM: &str = "the vault's disk has no room for this custody change's body past the \
     free-space reserve uploads keep (limits.disk_reserve_bytes): nothing was recorded";

/// What the owner can do about it.
const NO_ROOM_REMEDY: &str = "Free room on the vault's disk, then send the change again.";

/// A change's body, decoded: every member but the sealed input as `H`, and
/// the input's bytes in a file of their own, `None` when its member is not
/// standard base64. Dropped, after the change returns, the file goes and the
/// room the stored input holds on the floor is given back.
pub(super) struct SealedRequest<H> {
    pub(super) head: H,
    pub(super) input: Option<SpooledField>,
    _room: Option<Arc<DiskClaim>>,
}

/// Spools `body` whole under the disk floor and the transfers' idle bound,
/// as before, on a transfer worker, then decodes it there. A declared body claims its spool and its stored copy on
/// the floor before a byte of it is read; a body of no declared length
/// claims each next stretch as it goes. At its end the claim is the stored
/// copy, held by the returned request.
pub(super) async fn read<H: DeserializeOwned + Send + 'static>(
    server: &SyncServer,
    headers: &HeaderMap,
    body: Body,
) -> Result<SealedRequest<H>, ApiError> {
    let vault = Arc::clone(&server.vault);
    let read = body_spool::spool_then(
        server,
        body_spool::declared_length(headers),
        body,
        SpoolPolicy::custody(server),
        move |mut spool| {
            let file = vault
                .archive_spool_file()
                .map_err(|error| refusal(body_spool::create_failed(error)))?;
            let head_file = vault
                .archive_spool_file()
                .map_err(|error| refusal(body_spool::create_failed(error)))?;
            let (syntax, head, input) = {
                let mut memory = spool
                    .admit_sealed_decode_buffers()
                    .map_err(body_spool::sealed_decode_memory_refused)?;
                let mut input = Base64FileSink::new_admitted(file, &mut memory);
                let mut head = TextFileSink::new_admitted(head_file, &mut memory);
                let syntax = spool.object_head_admitted(
                    &mut [BulkMember::required(INPUT_MEMBER, &mut input)],
                    &mut head,
                    &mut memory,
                );
                (syntax, head.into_field(), input.into_field())
            };
            // No working buffer or lease survives into the next admission.
            // Known syntax or head-file failures never wait for another reader.
            syntax.map_err(|error| match error {
                HeadFail::Invalid => body_spool::invalid_json(),
                HeadFail::Failed => refusal(Unspooled::Failed),
            })?;
            let head = {
                let head_file = head.map_err(refusal)?;
                let mut memory = spool
                    .admit_reader()
                    .map_err(body_spool::sealed_decode_memory_refused)?;
                head_file.json_admitted::<H>(&mut memory).map_err(|error| {
                    if error.is_io() {
                        refusal(Unspooled::Failed)
                    } else {
                        body_spool::invalid_json()
                    }
                })?
            };
            Ok::<_, ApiError>((head, input, spool.into_room()))
        },
    )
    .await;
    let (head, input, room) = read.map_err(refusal)??;
    let input = match input {
        Ok(field) => Some(field),
        Err(SinkRefusal::NotBase64) => None,
        Err(SinkRefusal::NoRoom) => return Err(refusal(Unspooled::NoRoom)),
        Err(SinkRefusal::Failed) => return Err(refusal(Unspooled::Failed)),
    };
    Ok(SealedRequest {
        head,
        input,
        _room: room,
    })
}

/// A body the floor or the disk had no room for says capacity, in the
/// custody change's words. Memory admission keeps its own response; a body
/// that did not arrive keeps its existing failure.
fn refusal(unspooled: Unspooled) -> ApiError {
    match unspooled {
        Unspooled::NoRoom => body_spool::no_room(NO_ROOM, NO_ROOM_REMEDY),
        Unspooled::Failed => body_spool::not_whole(),
        refused @ Unspooled::MemoryRefused(_) => refused.refusal(),
    }
}
