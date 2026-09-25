//! Async HTTP bodies bridged to blocking vault IO with bounded backpressure.

use super::support::lfs_engine_error;
use crate::error::ApiError;
use axum::body::{Body, Bytes};
use futures_util::{StreamExt, stream};
use oneiron::origin::lfs::{LFS_CHUNK_MAX, LfsOid, LfsPutOutcome};
use oneiron::{TimeRange, Vault};
use std::io::{self, Read, Write};
use std::sync::Arc;
use tokio::sync::mpsc;

struct ChannelReader {
    receiver: mpsc::Receiver<io::Result<Option<Bytes>>>,
    current: Bytes,
    offset: usize,
    eof: bool,
}
impl Read for ChannelReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.offset == self.current.len() && !self.eof {
            match self.receiver.blocking_recv() {
                Some(Ok(Some(bytes))) => {
                    self.current = bytes;
                    self.offset = 0;
                }
                Some(Ok(None)) => self.eof = true,
                Some(Err(error)) => return Err(error),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "lfs upload cancelled",
                    ));
                }
            }
        }
        let count = output.len().min(self.current.len() - self.offset);
        output[..count].copy_from_slice(&self.current[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

pub(super) async fn upload(
    vault: Arc<Vault>,
    oid: LfsOid,
    size: Option<u64>,
    body: Body,
    now: u64,
) -> Result<LfsPutOutcome, ApiError> {
    let (sender, receiver) = mpsc::channel(2);
    let worker = tokio::task::spawn_blocking(move || {
        vault.put_lfs_object_stream(
            oid,
            size,
            ChannelReader {
                receiver,
                current: Bytes::new(),
                offset: 0,
                eof: false,
            },
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
    });
    let mut stream = body.into_data_stream();
    let mut failed = false;
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(bytes) => {
                // Copy each bounded slice. Bytes::slice would retain a hostile
                // giant backing allocation for every queued small fragment.
                for part in bytes.chunks(LFS_CHUNK_MAX) {
                    if sender
                        .send(Ok(Some(Bytes::copy_from_slice(part))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                if sender.is_closed() {
                    failed = true;
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(Err(io::Error::other(error.to_string()))).await;
                failed = true;
                break;
            }
        }
    }
    if !failed {
        let _ = sender.send(Ok(None)).await;
    }
    drop(sender);
    worker
        .await
        .map_err(|_| ApiError::internal_server_error("lfs upload worker failed"))?
        .map_err(|e| lfs_engine_error("lfs streaming upload failed", &e))
}

struct ChannelWriter(mpsc::Sender<io::Result<Bytes>>);
impl Write for ChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for part in bytes.chunks(LFS_CHUNK_MAX) {
            self.0
                .blocking_send(Ok(Bytes::copy_from_slice(part)))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "lfs download disconnected")
                })?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn download(vault: Arc<Vault>, oid: LfsOid) -> Body {
    let (sender, receiver) = mpsc::channel(2);
    tokio::task::spawn_blocking(move || {
        let result = vault.write_lfs_object_to(oid, &mut ChannelWriter(sender.clone()));
        match result {
            Ok(true) => {}
            Ok(false) => {
                let _ = sender.blocking_send(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "lfs object deleted",
                )));
            }
            Err(error) => {
                let _ = sender.blocking_send(Err(io::Error::other(error.to_string())));
            }
        }
    });
    Body::from_stream(stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    }))
}
