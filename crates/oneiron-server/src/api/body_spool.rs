//! An owner request's body, spooled (FIX 8195, FIX 7917, Rule 5). A body is
//! read only after its route's door admitted the caller, onto an anonymous
//! file the vault stages, whatever its length: its size never refuses it.
//! Only a disk that refuses a write for want of room stops it, and the answer
//! says capacity (`disk_capacity`). The sealed custody change also judges its
//! spool against the server's disk floor as it goes (`transfers.disk`, kept
//! at `limits.disk_reserve_bytes`, FIX 5674) and keeps the transfers' idle
//! bound on its body; no other route does either.
//!
//! [`OwnerJsonBody`] is every owner JSON route's body. [`json`] decodes a
//! spooled document whole while its bulk string members stream to sinks, so
//! a field of any length never becomes one string in memory.

mod json;
mod owner_json;

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, header};
use tokio::sync::mpsc;

use crate::api::transfer::{self, BodyReader};
use crate::error::{ApiError, ApiErrorDetails};
use crate::machine::{DiskClaim, DiskFloor};
use crate::owner::backup::write_budget::{CAPACITY_STATE, Capacity};
use crate::server::SyncServer;

pub(super) use self::json::{Base64FileSink, BulkMember, JsonInvalid, SinkRefusal, SpooledField};
pub(super) use self::owner_json::OwnerJsonBody;

/// Bytes the spool reads at a time, and the largest piece the body is fed in.
const SPOOL_PIECE: usize = 64 * 1024;

/// Bytes a body of no declared length spools between looks at the disk
/// floor; each look claims the stretch to the next one.
const FLOOR_EVERY_BYTES: u64 = 8 * 1024 * 1024;

/// What a request body the vault's disk had no room for says.
const NO_ROOM: &str = "the vault's disk has no room for this request's body: nothing was done";

/// What the owner can do about it.
const NO_ROOM_REMEDY: &str = "Free room on the vault's disk, then send the request again.";

/// A request body whole on the vault's disk, read from its start. Dropped,
/// the spool goes, and the room it claimed on the disk floor, if any, is
/// given back.
pub(super) struct BodySpool {
    file: File,
    room: Option<Arc<DiskClaim>>,
}

impl BodySpool {
    /// The spool as one JSON document `T`, decoded as it is read; `None`
    /// when it is not one.
    pub(super) fn json<T: serde::de::DeserializeOwned>(&mut self) -> Option<T> {
        serde_json::from_reader(BufReader::with_capacity(SPOOL_PIECE, &mut self.file)).ok()
    }

    /// The spool as one JSON object `T`, with each bulk member's string
    /// streamed to its sink as it is read (`json::decode_object`).
    pub(super) fn object<T: serde::de::DeserializeOwned>(
        &mut self,
        bulk: &mut [BulkMember<'_>],
    ) -> Result<T, JsonInvalid> {
        json::decode_object(BufReader::with_capacity(SPOOL_PIECE, &mut self.file), bulk)
    }

    /// The room the spool holds on the disk floor, kept past the spool.
    pub(super) fn into_room(self) -> Option<Arc<DiskClaim>> {
        self.room
    }
}

/// How a body ended before it was spooled.
pub(super) enum Unspooled {
    /// The vault's disk refused a write for want of room, or reached the
    /// floor's free-space reserve.
    NoRoom,
    /// The body failed, stalled past the idle limit or was cancelled, or its
    /// spool could not be written.
    Failed,
}

impl Unspooled {
    /// The answer an owner route gives: capacity, or a body that did not
    /// arrive.
    pub(super) fn refusal(self) -> ApiError {
        match self {
            Self::NoRoom => no_room(NO_ROOM, NO_ROOM_REMEDY),
            Self::Failed => not_whole(),
        }
    }
}

/// The length `headers` declare for the body.
pub(super) fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

/// How a spool reads its body: the disk floor it is judged against, and the
/// longest the client may go quiet between frames. Every owner route reads
/// with neither, so only the listener's own body policy ends a quiet body;
/// the custody change keeps both ([`Self::custody`]).
#[derive(Default)]
pub(super) struct SpoolPolicy {
    floor: Option<DiskFloor>,
    idle: Option<Duration>,
}

impl SpoolPolicy {
    /// The custody change's policy, as before this spool was shared: the
    /// server's disk floor and the transfers' idle bound.
    pub(super) fn custody(server: &SyncServer) -> Self {
        Self {
            floor: Some(server.transfers.disk.clone()),
            idle: Some(server.transfers.idle),
        }
    }
}

/// Spools `body` whole on a transfer worker, then runs `then` over the spool
/// on that worker. With a floor, a declared body claims its spool and its
/// stored copy on it before a byte of it is read, and a body of no declared
/// length claims each next stretch as it goes; at its end the claim is the
/// stored copy, held by the spool.
pub(super) async fn spool_then<R: Send + 'static>(
    server: &SyncServer,
    declared: Option<u64>,
    body: Body,
    policy: SpoolPolicy,
    then: impl FnOnce(BodySpool) -> R + Send + 'static,
) -> Result<R, Unspooled> {
    let SpoolPolicy { floor, idle } = policy;
    let room = match &floor {
        Some(floor) => {
            let claim = floor.claim();
            if let Some(size) = declared
                && !floor.hold(&claim, size.saturating_mul(2))
            {
                return Err(Unspooled::NoRoom);
            }
            Some(claim)
        }
        None => None,
    };
    let vault = Arc::clone(&server.vault);
    let (sender, receiver) = mpsc::channel(2);
    let mut worker = transfer::spawn_worker(move || -> Result<R, Unspooled> {
        let account = floor.as_ref().zip(room.as_deref());
        let file = spool_to_end(&vault, BodyReader::new(receiver), account, declared)?;
        Ok(then(BodySpool { file, room }))
    });
    // The worker can end at the floor before the client sends its next
    // frame, so its answer is taken without waiting for the body to end.
    let feed = async move {
        match idle {
            Some(idle) => transfer::feed_body(body, sender, idle, SPOOL_PIECE).await,
            None => transfer::feed_body_untimed(body, sender, SPOOL_PIECE).await,
        }
    };
    let early = tokio::select! {
        biased;
        joined = &mut worker => Some(joined),
        () = feed => None,
    };
    let joined = match early {
        Some(joined) => joined,
        None => worker.await,
    };
    joined.unwrap_or(Err(Unspooled::Failed))
}

/// The body to its end in a vault-staged spool. Against a floor it is
/// judged as it goes: each look moves the claim to what is still to be
/// written, the spool's rest and its stored copy, so no other upload counts
/// that room as free, and at its end the claim is its stored copy.
fn spool_to_end(
    vault: &oneiron::Vault,
    mut body: BodyReader,
    floor: Option<(&DiskFloor, &DiskClaim)>,
    declared: Option<u64>,
) -> Result<File, Unspooled> {
    let mut file = vault.archive_spool_file().map_err(create_failed)?;
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
        if let Some((floor, claim)) = floor
            && looked_at.is_none_or(|at| read.saturating_sub(at) >= FLOOR_EVERY_BYTES)
        {
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
    if let Some((floor, claim)) = floor
        && !floor.hold(claim, read)
    {
        return Err(Unspooled::NoRoom);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Unspooled::Failed)?;
    Ok(file)
}

/// A spool file the disk had no room to create says capacity, told by its
/// type, as a write does; any other failure is the body's.
pub(super) fn create_failed(error: oneiron::Error) -> Unspooled {
    if Capacity::of(&error).is_some() {
        Unspooled::NoRoom
    } else {
        Unspooled::Failed
    }
}

/// A spool write the disk refused for want of room says capacity, told by
/// its type (FIX 5615); any other failure is the body's.
pub(super) fn write_failed(error: io::Error) -> Unspooled {
    if error.kind() == io::ErrorKind::StorageFull {
        Unspooled::NoRoom
    } else {
        Unspooled::Failed
    }
}

/// The vault's disk has no room for the body: the only refusal its size can
/// meet, in the shape every owner route gives capacity.
pub(super) fn no_room(message: &str, remedy: &str) -> ApiError {
    ApiError::new(
        message,
        ApiErrorDetails::InvalidState {
            state: Some(CAPACITY_STATE.to_owned()),
        },
        [remedy],
    )
}

/// A body that failed, stalled or was cancelled before its end.
pub(super) fn not_whole() -> ApiError {
    ApiError::bad_request("the request body did not arrive whole", None)
}

/// A body that is not the JSON its route reads, as every owner route says it.
pub(super) fn invalid_json() -> ApiError {
    ApiError::bad_request("invalid JSON request body", None)
}
