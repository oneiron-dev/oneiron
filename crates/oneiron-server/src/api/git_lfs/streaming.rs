//! Async HTTP bodies bridged to blocking vault IO with bounded backpressure.

use super::support::lfs_engine_error;
use crate::admission::Permit;
use crate::api::transfer::{self, BodyReader, Reservation};
use crate::error::ApiError;
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use axum::body::{Body, Bytes};
use futures_util::stream;
use oneiron::origin::lfs::{LFS_CHUNK_MAX, LfsOid, LfsPutOutcome};
use oneiron::{TimeRange, Vault};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// What an upload holds while its worker runs: a transfer permit and its
/// room in the LFS quota. Both go when the worker does, not when the handler
/// does.
pub(super) type UploadHold = (Permit, Reservation);

/// How often, in bytes read, an upload looks at the disk again.
const FLOOR_EVERY_BYTES: u64 = 8 * 1024 * 1024;

/// The vault disk's free-space reserve: the floor an upload is refused at.
#[derive(Clone)]
pub(super) struct DiskFloor {
    dir: PathBuf,
    reserve: u64,
}

impl DiskFloor {
    pub(super) fn new(dir: PathBuf, reserve: u64) -> Self {
        Self { dir, reserve }
    }

    /// Whether `bytes` more still leave the reserve free. A disk that cannot
    /// be read is taken as full: a floor that cannot be checked holds.
    pub(super) fn has_room_for(&self, bytes: u64) -> bool {
        crate::machine::free_disk_bytes(&self.dir)
            .is_ok_and(|free| free >= self.reserve.saturating_add(bytes))
    }
}

/// One upload's terms, fixed before its worker starts.
pub(super) struct UploadTerms {
    pub(super) oid: LfsOid,
    pub(super) declared: Option<u64>,
    /// The per-object size row: past it the upload carries on and asks.
    pub(super) size_row: u64,
    pub(super) floor: DiskFloor,
    pub(super) questions: Arc<LimitQuestions>,
    pub(super) now: u64,
    pub(super) idle: Duration,
}

/// Streams `body` into the vault. `None` when the upload reached the disk
/// floor and was ended there, nothing stored.
pub(super) async fn upload(
    vault: Arc<Vault>,
    terms: UploadTerms,
    body: Body,
    hold: UploadHold,
) -> Result<Option<LfsPutOutcome>, ApiError> {
    let UploadTerms {
        oid,
        declared,
        size_row,
        floor,
        questions,
        now,
        idle,
    } = terms;
    let (sender, receiver) = mpsc::channel(2);
    let floored = Arc::new(AtomicBool::new(false));
    let reader = FloorReader {
        body: BodyReader::new(receiver),
        floor,
        floored: Arc::clone(&floored),
        size_row,
        questions,
        read: 0,
        looked_at: None,
        asked: declared.is_some_and(|size| size > size_row),
    };
    let mut worker = tokio::task::spawn_blocking(move || {
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
        return Ok(None);
    }
    finished(joined).map(Some)
}

/// The request body, as the engine reads it, judged against the disk floor
/// as it goes and against the room its stored copy needs at its end. Past
/// the size row it carries on and asks once.
struct FloorReader {
    body: BodyReader,
    floor: DiskFloor,
    floored: Arc<AtomicBool>,
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
        self.read = self.read.saturating_add(count as u64);
        if !self.asked && self.read > self.size_row {
            self.asked = true;
            self.questions
                .ask(LimitRow::LfsObjectSize, self.size_row, self.read);
        }
        // The spool takes the disk as the body arrives; at the end, the
        // stored copy needs as much again.
        let needed = if count == 0 {
            Some(self.read)
        } else if self
            .looked_at
            .is_none_or(|at| self.read - at >= FLOOR_EVERY_BYTES)
        {
            Some(0)
        } else {
            None
        };
        if let Some(needed) = needed {
            self.looked_at = Some(self.read);
            if !self.floor.has_room_for(needed) {
                self.floored.store(true, Ordering::SeqCst);
                return Err(io::Error::other("the vault's disk reached its reserve"));
            }
        }
        Ok(count)
    }
}

fn finished(
    joined: Result<oneiron::Result<LfsPutOutcome>, tokio::task::JoinError>,
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

/// Streams one stored object out. The worker holds `permit` until it has
/// written the last byte or its client stopped reading.
pub(super) fn download(vault: Arc<Vault>, oid: LfsOid, permit: Permit, idle: Duration) -> Body {
    let (sender, receiver) = mpsc::channel(2);
    let reader = Arc::clone(&vault);
    let runtime = Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
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
    });
    // Each buffered chunk is released only while no device-only world keeps
    // the object; a flag set mid-download ends the body with an error.
    Body::from_stream(stream::unfold(receiver, move |mut receiver| {
        let vault = Arc::clone(&vault);
        async move {
            let item = receiver.recv().await?;
            let item = match item {
                Ok(_)
                    if oneiron::sync::chunks::lfs_object_withheld(&vault, oid).unwrap_or(true) =>
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
