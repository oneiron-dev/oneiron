//! Async HTTP bodies bridged to blocking vault IO with bounded backpressure.

use super::support::lfs_engine_error;
use crate::admission::Permit;
use crate::api::transfer::{self, BodyReader, DECODED_PER_BYTE, ReadHold, Reservation};
use crate::byte_line::{ByteLine, HeldBytes};
use crate::error::ApiError;
use crate::machine::{DiskClaim, DiskFloor};
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use axum::body::{Body, Bytes};
use futures_util::stream;
use oneiron::origin::lfs::{
    LFS_CHUNK_MAX, LFS_CHUNK_MIN, LFS_WHOLE_SCAN_MAX, LfsOid, LfsPutOutcome,
};
use oneiron::{TimeRange, Vault};
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// What an upload holds while its worker runs: a transfer permit and its
/// claim on the disk. Both go when the worker does (after the stored copy is
/// written), not when the handler does; so does its room in the LFS quota,
/// which its body reader holds.
pub(super) type UploadHold = (Permit, Arc<DiskClaim>);

/// How often, in bytes read, an upload looks at the disk again.
const FLOOR_EVERY_BYTES: u64 = 8 * 1024 * 1024;

/// The room the stored copy of a `bytes` object may take on the vault's
/// disk, its storage written in `page`-byte pages: its chunks, every one but
/// the last at least [`LFS_CHUNK_MIN`], each taking at most a page more than
/// its bytes once rounded up to whole pages, and the rows each adds, counted
/// at [`CHUNK_ROWS`]; and what every object takes whatever its size, its
/// spool's last block, its manifest and its rows, counted at
/// [`OBJECT_ROOM`]. Copy-on-write growth while readers hold old pages is not
/// counted; the reserve is the margin for it.
pub(super) fn stored_copy(bytes: u64, page: u64) -> u64 {
    let chunks = (bytes / LFS_CHUNK_MIN as u64).saturating_add(1);
    bytes
        .saturating_add(chunks.saturating_mul(page.saturating_add(CHUNK_ROWS)))
        .saturating_add(OBJECT_ROOM)
}

/// The rows one stored chunk adds, and the room they take, counted
/// generously.
const CHUNK_ROWS: u64 = 4 * 1024;

/// What one stored object takes on the disk whatever its size.
const OBJECT_ROOM: u64 = 64 * 1024;

/// The room in memory an install of a `bytes` object takes, from the end of
/// its body until it is stored. Up to the engine's whole-object bound
/// ([`LFS_WHOLE_SCAN_MAX`]) the object is held whole and its credential scan
/// decodes it as one structured body, `DECODED_PER_BYTE` bytes a byte at
/// most; above it each chunk is decoded alone and the stream's seam holds
/// what an edge splits, up to the same bound, as bytes and as text
/// ([`SEAM_ROOM`]). Its manifest takes [`CHUNK_META`] for each chunk it may
/// have, and the install [`INSTALL_ROOM`] whatever its size.
pub(super) fn install_room(bytes: u64) -> u64 {
    let chunk = LFS_CHUNK_MAX as u64;
    let decoded = if bytes <= LFS_WHOLE_SCAN_MAX {
        bytes.saturating_mul(DECODED_PER_BYTE)
    } else {
        SEAM_ROOM.saturating_add(chunk.saturating_mul(DECODED_PER_BYTE))
    };
    let chunks = (bytes / LFS_CHUNK_MIN as u64).saturating_add(1);
    decoded
        .saturating_add(chunks.saturating_mul(CHUNK_META))
        .saturating_add(INSTALL_ROOM)
}

/// What the seam of an object read in chunks holds: a segment of up to the
/// whole-object bound, as bytes and as text (up to three bytes a byte), with
/// room for the buffers' growth.
const SEAM_ROOM: u64 = 6 * LFS_WHOLE_SCAN_MAX;

/// What one chunk adds to an install: its reference as the manifest is built
/// (a vector that grows by doubling), the manifest's encoding and the copy
/// its id is hashed from, and its place in the set of chunks stored so far,
/// counted generously.
const CHUNK_META: u64 = 256;

/// What an install holds whatever its object's size: its read and chunking
/// buffers, a chunk as read and as written, and the transaction's pages
/// (0.2 MiB for a 1 KiB object, measured as `DECODED_PER_BYTE` was), counted
/// generously.
const INSTALL_ROOM: u64 = 4 * 1024 * 1024;

/// One upload's terms, fixed before its worker starts.
pub(super) struct UploadTerms {
    pub(super) oid: LfsOid,
    pub(super) declared: Option<u64>,
    /// The per-object size row: past it the upload carries on and asks.
    pub(super) size_row: u64,
    pub(super) floor: DiskFloor,
    /// The page size the vault's object plane is stored in.
    pub(super) page: u64,
    /// Its room in the LFS quota, grown at its end to what it came to.
    pub(super) reservation: Reservation,
    /// Where it takes its room in memory once its body is spooled
    /// ([`install_room`]), waiting up to `wait`.
    pub(super) installs: Arc<ByteLine>,
    pub(super) wait: Duration,
    pub(super) questions: Arc<LimitQuestions>,
    pub(super) now: u64,
    pub(super) idle: Duration,
}

/// How an upload ended.
pub(super) enum Uploaded {
    Stored(LfsPutOutcome),
    /// It reached the disk floor and was ended there, nothing stored.
    Floored,
    /// Its body was spooled, but it waited past its deadline for room in
    /// memory to be installed; nothing stored.
    WaitedOut,
}

/// Streams `body` into the vault.
pub(super) async fn upload(
    vault: Arc<Vault>,
    terms: UploadTerms,
    body: Body,
    hold: UploadHold,
) -> Result<Uploaded, ApiError> {
    let UploadTerms {
        oid,
        declared,
        size_row,
        floor,
        page,
        reservation,
        installs,
        wait,
        questions,
        now,
        idle,
    } = terms;
    let (sender, receiver) = mpsc::channel(2);
    let floored = Arc::new(AtomicBool::new(false));
    let waited = Arc::new(AtomicBool::new(false));
    let reader = FloorReader {
        body: BodyReader::new(receiver),
        vault: Arc::clone(&vault),
        floor,
        page,
        claim: Arc::clone(&hold.1),
        reservation,
        declared,
        floored: Arc::clone(&floored),
        installs,
        wait,
        runtime: Handle::current(),
        installing: None,
        waited: Arc::clone(&waited),
        size_row,
        questions,
        read: 0,
        looked_at: None,
        asked: declared.is_some_and(|size| size > size_row),
    };
    let mut worker = transfer::spawn_worker(move || {
        let _hold = hold;
        // The size row is not a cap: only the disk floor ends an upload.
        vault.put_lfs_object_stream_with_cap(
            oid,
            declared,
            u64::MAX,
            reader,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
    });
    // The engine can reject a frame before the client sends another one, so
    // its refusal is returned without waiting for the body to end.
    let early = tokio::select! {
        biased;
        result = &mut worker => Some(result),
        () = transfer::feed_body(body, sender, idle, LFS_CHUNK_MAX) => None,
    };
    let joined = match early {
        Some(result) => result,
        None => worker.await,
    };
    if floored.load(Ordering::SeqCst) {
        return Ok(Uploaded::Floored);
    }
    if waited.load(Ordering::SeqCst) {
        return Ok(Uploaded::WaitedOut);
    }
    finished(joined).map(Uploaded::Stored)
}

/// The request body, as the engine reads it, judged against the disk floor
/// as it goes and against the room its stored copy needs at its end. Each
/// look moves the upload's claim to what it has still to write, so no other
/// upload counts that room as free. Past the size row it carries on and asks
/// once; at its end its quota reservation grows to what it came to, and it
/// takes its room in memory for the install the engine starts once the body
/// ends. The engine holds the reader until the object is stored, so the room
/// is held that long.
struct FloorReader {
    body: BodyReader,
    vault: Arc<Vault>,
    floor: DiskFloor,
    page: u64,
    claim: Arc<DiskClaim>,
    reservation: Reservation,
    declared: Option<u64>,
    floored: Arc<AtomicBool>,
    installs: Arc<ByteLine>,
    wait: Duration,
    /// The runtime the wait for the install's room runs on, from the
    /// upload's worker.
    runtime: Handle,
    /// The install's room, once the body has ended.
    installing: Option<HeldBytes>,
    waited: Arc<AtomicBool>,
    size_row: u64,
    questions: Arc<LimitQuestions>,
    read: u64,
    /// Bytes read when the disk was last looked at; `None` before the first
    /// piece, which is looked at at once.
    looked_at: Option<u64>,
    asked: bool,
}

impl Read for FloorReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.body.read(output)?;
        // The engine writes each piece to its spool before it reads the
        // next, so every piece before this one is on the disk already, gone
        // from its free space, and this one is not.
        let written = self.read;
        self.read = self.read.saturating_add(count as u64);
        if !self.asked && self.read > self.size_row {
            self.asked = true;
            self.questions
                .ask(LimitRow::LfsObjectSize, self.size_row, self.read);
        }
        // At the end the spool is whole and the stored copy needs as much
        // again. Before it, a declared upload still has its spool's rest and
        // its stored copy to write. One with no declaration claims this piece
        // and all it may write before its next look, and its stored copy at
        // its end, once its size is known.
        let needed = if count == 0 {
            self.reservation.cover(&self.vault, self.read);
            Some(stored_copy(self.read, self.page))
        } else if self
            .looked_at
            .is_none_or(|at| self.read - at >= FLOOR_EVERY_BYTES)
        {
            Some(self.declared.map_or(
                (count as u64).saturating_add(FLOOR_EVERY_BYTES),
                |declared| {
                    declared
                        .saturating_sub(written)
                        .saturating_add(stored_copy(declared.max(self.read), self.page))
                },
            ))
        } else {
            None
        };
        if let Some(needed) = needed {
            self.looked_at = Some(self.read);
            if !self.floor.hold(&self.claim, needed) {
                self.floored.store(true, Ordering::SeqCst);
                return Err(io::Error::other("the vault's disk reached its reserve"));
            }
        }
        // The body is whole: what remains is the install, which no client
        // holds up, so the wait for its room is a wait on the server's own
        // work. One larger than the whole line waits to install alone.
        if count == 0 && self.installing.is_none() {
            let room = usize::try_from(install_room(self.read)).unwrap_or(usize::MAX);
            let Some(room) = self.runtime.block_on(self.installs.reserve_alone(
                room,
                self.wait,
                &self.questions,
            )) else {
                self.waited.store(true, Ordering::SeqCst);
                return Err(io::Error::other("the upload waited past its deadline"));
            };
            self.installing = Some(room);
        }
        Ok(count)
    }
}

fn finished(
    joined: Result<oneiron::Result<LfsPutOutcome>, transfer::WorkerGone>,
) -> Result<LfsPutOutcome, ApiError> {
    joined
        .map_err(|_| ApiError::internal_server_error("lfs upload worker failed"))?
        .map_err(|e| lfs_engine_error("lfs streaming upload failed", &e))
}

/// The download body, as a blocking writer onto the async stream. A client
/// that stops reading ends it at the idle limit.
struct ChannelWriter {
    chunks: mpsc::Sender<io::Result<Bytes>>,
    runtime: Handle,
    idle: Duration,
}

impl Write for ChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for part in bytes.chunks(LFS_CHUNK_MAX) {
            transfer::send_within(
                &self.runtime,
                &self.chunks,
                Ok(Bytes::copy_from_slice(part)),
                self.idle,
            )?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Streams one stored object out. The worker holds `hold` until it has
/// written the last byte or its client stopped reading. Each piece is judged
/// for `peer`, the machine the request proved (FIX 4937).
pub(super) fn download(
    vault: Arc<Vault>,
    (oid, peer): (LfsOid, oneiron::authority::PeerMachine),
    hold: ReadHold,
    idle: Duration,
) -> Body {
    let (sender, receiver) = mpsc::channel(2);
    let reader = Arc::clone(&vault);
    let runtime = Handle::current();
    // Detached: the worker answers nobody; it ends with the stream.
    drop(transfer::spawn_worker(move || {
        let _hold = hold;
        let mut writer = ChannelWriter {
            chunks: sender,
            runtime,
            idle,
        };
        let ending = match reader.write_lfs_object_to(oid, &mut writer) {
            Ok(true) => return,
            Ok(false) => io::Error::new(io::ErrorKind::NotFound, "lfs object deleted"),
            Err(error) => io::Error::other(error.to_string()),
        };
        // Bounded like every other chunk: a client that stopped reading
        // never takes this worker with it.
        let _ = transfer::send_within(&writer.runtime, &writer.chunks, Err(ending), idle);
    }));
    // Each buffered chunk is released only while no world withheld from the
    // peer keeps the object; a flag set mid-download ends the body with an
    // error.
    Body::from_stream(stream::unfold(receiver, move |mut receiver| {
        let vault = Arc::clone(&vault);
        async move {
            let item = receiver.recv().await?;
            let item = match item {
                Ok(_)
                    if oneiron::sync::chunks::lfs_object_withheld_for(&vault, oid, peer)
                        .unwrap_or(true) =>
                {
                    receiver.close();
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "lfs object kept on this device",
                    ))
                }
                item => item,
            };
            Some((item, receiver))
        }
    }))
}
