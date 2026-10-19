//! The sealed custody change's body, spooled (FIX 5674, Rule 5). `POST
//! /v1/owner/secrets/custody` reads its body after the owner door, whatever
//! its length, onto an anonymous file the vault stages, under the server's
//! one disk floor (`transfers.disk`, kept at `limits.disk_reserve_bytes`), as
//! the signing doors spool theirs. A surface's frame of numbered envelopes
//! (FIX 5521) is read as one envelope is. Only that floor, or a disk that
//! refuses a write for want of room, stops it, and the answer says capacity
//! (`disk_capacity`); its size never does (CALLS OWNER_CUSTODY_BODY_SPOOL).
//! The body is ciphertext sealed to the holder, and its spool is gone once
//! dropped.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, header};
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;

use crate::api::transfer::{self, BodyReader};
use crate::error::{ApiError, ApiErrorDetails};
use crate::machine::{DiskClaim, DiskFloor};
use crate::owner::backup::write_budget::CAPACITY_STATE;
use crate::server::SyncServer;

/// Bytes the spool reads at a time, and the largest piece the body is fed in.
const SPOOL_PIECE: usize = 64 * 1024;

/// Bytes a body of no declared length spools between looks at the disk
/// floor; each look claims the stretch to the next one.
const FLOOR_EVERY_BYTES: u64 = 8 * 1024 * 1024;

/// What a change the vault's disk had no room for says.
const NO_ROOM: &str = "the vault's disk has no room for this custody change's body past the \
     free-space reserve uploads keep (limits.disk_reserve_bytes): nothing was recorded";

/// What the owner can do about it.
const NO_ROOM_REMEDY: &str = "Free room on the vault's disk, then send the change again.";

/// A change's body whole on the vault's disk, and the room the sealed input
/// the engine stores from it holds on the floor. Dropped, after the change
/// returns, the spool goes and the room is given back.
pub(super) struct SpooledBody {
    file: File,
    _room: Arc<DiskClaim>,
}

impl SpooledBody {
    /// The body as JSON `T`; `None` when it is not one.
    pub(super) fn json<T: DeserializeOwned>(&mut self) -> Option<T> {
        serde_json::from_reader(BufReader::new(&mut self.file)).ok()
    }
}

/// How a body ended before it was read.
enum Unspooled {
    /// The vault's disk reached its free-space reserve, or refused a write
    /// for want of room.
    NoRoom,
    /// The body failed, stalled past the idle limit or was cancelled, or its
    /// spool could not be written.
    Failed,
}

/// Spools `body` whole on a transfer worker. A declared body claims its
/// spool and its stored copy on the floor before a byte of it is read; a
/// body of no declared length claims each next stretch as it goes. At its
/// end the claim is the stored copy, held by the returned body.
pub(super) async fn spool(
    server: &Arc<SyncServer>,
    headers: &HeaderMap,
    body: Body,
) -> Result<SpooledBody, ApiError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let floor = server.transfers.disk.clone();
    let claim = floor.claim();
    if let Some(size) = declared
        && !floor.hold(&claim, size.saturating_mul(2))
    {
        return Err(no_room());
    }
    let vault = Arc::clone(&server.vault);
    let (sender, receiver) = mpsc::channel(2);
    let mut worker = transfer::spawn_worker(move || -> Result<SpooledBody, Unspooled> {
        let file = spool_to_end(&vault, BodyReader::new(receiver), &floor, &claim, declared)?;
        Ok(SpooledBody { file, _room: claim })
    });
    // The worker can end at the floor before the client sends its next
    // frame, so its answer is taken without waiting for the body to end.
    let early = tokio::select! {
        biased;
        joined = &mut worker => Some(joined),
        () = transfer::feed_body(body, sender, server.transfers.idle, SPOOL_PIECE) => None,
    };
    let joined = match early {
        Some(joined) => joined,
        None => worker.await,
    };
    match joined {
        Ok(Ok(spooled)) => Ok(spooled),
        Ok(Err(Unspooled::NoRoom)) => Err(no_room()),
        Ok(Err(Unspooled::Failed)) | Err(_) => Err(ApiError::bad_request(
            "the request body did not arrive whole",
            None,
        )),
    }
}

/// The body to its end in a vault-staged spool, judged against the floor as
/// it goes: each look moves the claim to what is still to be written, the
/// spool's rest and its stored copy, so no other upload counts that room as
/// free. At its end the spool is on the disk, and the claim is its stored
/// copy.
fn spool_to_end(
    vault: &oneiron::Vault,
    mut body: BodyReader,
    floor: &DiskFloor,
    claim: &DiskClaim,
    declared: Option<u64>,
) -> Result<File, Unspooled> {
    let mut file = vault.archive_spool_file().map_err(|_| Unspooled::Failed)?;
    let mut piece = vec![0; SPOOL_PIECE];
    let mut read = 0u64;
    let mut looked_at: Option<u64> = None;
    loop {
        let count = body.read(&mut piece).map_err(|_| Unspooled::Failed)?;
        if count == 0 {
            break;
        }
        let written = read;
        read = read.saturating_add(count as u64);
        if looked_at.is_none_or(|at| read.saturating_sub(at) >= FLOOR_EVERY_BYTES) {
            looked_at = Some(read);
            let needed = declared
                .map_or((count as u64).saturating_add(FLOOR_EVERY_BYTES), |size| {
                    size.saturating_sub(written).saturating_add(size.max(read))
                });
            if !floor.hold(claim, needed) {
                return Err(Unspooled::NoRoom);
            }
        }
        file.write_all(&piece[..count]).map_err(write_failed)?;
    }
    if !floor.hold(claim, read) {
        return Err(Unspooled::NoRoom);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Unspooled::Failed)?;
    Ok(file)
}

/// A spool write the disk refused for want of room says capacity, told by
/// its type (FIX 5615); any other failure is the body's.
fn write_failed(error: io::Error) -> Unspooled {
    if error.kind() == io::ErrorKind::StorageFull {
        Unspooled::NoRoom
    } else {
        Unspooled::Failed
    }
}

/// The vault's disk has no room for the body: the only refusal its size can
/// meet, in the shape every owner route gives capacity.
fn no_room() -> ApiError {
    ApiError::new(
        NO_ROOM,
        ApiErrorDetails::InvalidState {
            state: Some(CAPACITY_STATE.to_owned()),
        },
        [NO_ROOM_REMEDY],
    )
}
