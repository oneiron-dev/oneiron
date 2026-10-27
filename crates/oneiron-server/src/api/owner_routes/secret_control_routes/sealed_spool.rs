//! The sealed custody change's body, spooled and decoded (FIX 5674, FIX 7917,
//! Rule 5). `POST /v1/owner/secrets/custody` reads its body after the owner
//! door, whatever its length, onto an anonymous file the vault stages
//! (`api::body_spool`), under the server's one disk floor (`transfers.disk`,
//! kept at `limits.disk_reserve_bytes`), as the signing doors spool theirs.
//! A surface's frame of numbered envelopes (FIX 5521) is read as one envelope
//! is. Only that floor, or a disk that refuses a write for want of room,
//! stops it, and the answer says capacity (`disk_capacity`); its size never
//! does (CALLS OWNER_CUSTODY_BODY_SPOOL). The sealed input is decoded from
//! its base64 into a file of its own as the spool is read, never one string
//! in memory. The body is ciphertext sealed to the holder, and both files
//! are gone once dropped.

use std::sync::Arc;

use axum::body::Body;
use axum::http::HeaderMap;
use serde::de::DeserializeOwned;

use crate::api::body_spool::{
    self, Base64FileSink, BulkMember, SinkRefusal, SpoolPolicy, SpooledField, Unspooled,
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
                .map_err(body_spool::create_failed)?;
            let mut input = Base64FileSink::new(file);
            let head = spool.object::<H>(&mut [BulkMember::required(INPUT_MEMBER, &mut input)]);
            Ok::<_, Unspooled>((head, input.into_field(), spool.into_room()))
        },
    )
    .await;
    let (head, input, room) = match read {
        Ok(Ok(read)) => read,
        Ok(Err(unspooled)) | Err(unspooled) => return Err(refusal(unspooled)),
    };
    let head = head.map_err(|_| body_spool::invalid_json())?;
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
/// custody change's words; any other failure is the body's.
fn refusal(unspooled: Unspooled) -> ApiError {
    match unspooled {
        Unspooled::NoRoom => body_spool::no_room(NO_ROOM, NO_ROOM_REMEDY),
        Unspooled::Failed => body_spool::not_whole(),
    }
}
