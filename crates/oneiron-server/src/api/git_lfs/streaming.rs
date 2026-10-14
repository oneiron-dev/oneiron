//! Async HTTP bodies bridged to blocking vault IO with bounded backpressure.

use super::support::{lfs_engine_error, lfs_object_withheld_now};
use crate::admission::Permit;
use crate::api::transfer::{self, BodyReader, Reservation};
use crate::error::ApiError;
use axum::body::{Body, Bytes};
use futures_util::stream;
use oneiron::origin::lfs::{LFS_CHUNK_MAX, LfsOid, LfsPutOutcome};
use oneiron::{TimeRange, Vault};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

/// What an upload holds while its worker runs: a transfer permit and its
/// room in the LFS quota. Both go when the worker does, not when the handler
/// does.
pub(super) type UploadHold = (Permit<String>, Reservation);

#[expect(
    clippy::too_many_arguments,
    reason = "one upload's whole admission, each piece a different fact the worker needs"
)]
pub(super) async fn upload(
    vault: Arc<Vault>,
    oid: LfsOid,
    size: Option<u64>,
    max_object_bytes: u64,
    body: Body,
    now: u64,
    hold: UploadHold,
    idle: Duration,
) -> Result<LfsPutOutcome, ApiError> {
    let (sender, receiver) = mpsc::channel(2);
    let mut worker = tokio::task::spawn_blocking(move || {
        let _hold = hold;
        vault.put_lfs_object_stream_with_cap(
            oid,
            size,
            max_object_bytes,
            BodyReader::new(receiver),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
    });
    // The engine can reject a frame before the client sends another one, so
    // its refusal is returned without waiting for the body to end.
    tokio::select! {
        biased;
        result = &mut worker => return finished(result),
        () = transfer::feed_body(body, sender, idle, LFS_CHUNK_MAX) => {}
    }
    finished(worker.await)
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
pub(super) fn download(
    vault: Arc<Vault>,
    oid: LfsOid,
    permit: Permit<String>,
    idle: Duration,
) -> Body {
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
            if item.is_ok() && lfs_object_withheld_now(&vault, oid).await {
                receiver.close();
                let kept = io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "lfs object kept on this device",
                );
                return Some((Err(kept), receiver));
            }
            Some((item, receiver))
        }
    }))
}
