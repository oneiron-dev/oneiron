//! Bounded transfers between an HTTP body and a blocking worker, shared by
//! the git smart-HTTP and LFS bridges.
//!
//! A transfer takes a permit before its worker starts and the worker holds it
//! (see [`crate::admission`]), and each side waits on the other for a bounded
//! idle time only: a request body that stops arriving, or a response nobody
//! reads, ends the transfer with `TimedOut` rather than pinning the worker,
//! its child process or its spool for as long as the socket stays open. A
//! transfer that keeps moving, however slowly, is never cut.

use std::io::{self, Read};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::admission::{Admission, Permit, Saturated};
use crate::config::LimitsConfig;

/// The permits remotely started transfers take, and how long either side of
/// one may wait for the other.
pub(crate) struct Transfers {
    /// One `git http-backend` exchange each.
    git: Admission<String>,
    /// One LFS upload or download worker each.
    lfs: Admission<String>,
    /// Bytes LFS uploads may bring the vault's objects to.
    lfs_quota: u64,
    /// Bytes uploads in flight have reserved against `lfs_quota`.
    lfs_reserved: Arc<Mutex<u64>>,
    pub(crate) idle: Duration,
}

impl Transfers {
    pub(crate) fn new(limits: &LimitsConfig) -> Self {
        Self {
            git: Admission::new(limits.git_exchanges, limits.git_exchanges_per_principal),
            lfs: Admission::new(limits.lfs_transfers, limits.lfs_transfers_per_principal),
            lfs_quota: limits.lfs_quota_bytes,
            lfs_reserved: Arc::default(),
            idle: Duration::from_millis(limits.transfer_idle_timeout_ms),
        }
    }

    /// A git exchange's permit. Callers without a registered principal share
    /// one key.
    pub(super) fn admit_git(&self, principal: Option<&str>) -> Result<Permit<String>, Saturated> {
        self.git.try_admit(principal.unwrap_or_default().to_owned())
    }

    /// An LFS transfer's permit, keyed as [`Self::admit_git`] is.
    pub(super) fn admit_lfs(&self, principal: Option<&str>) -> Result<Permit<String>, Saturated> {
        self.lfs.try_admit(principal.unwrap_or_default().to_owned())
    }

    /// Reserves `bytes` of the LFS quota for one upload, judged against what
    /// the vault's objects hold now and what other uploads have reserved;
    /// `None` when it does not fit. The upload's worker holds the reservation
    /// until it ends, by which time a stored object counts in its own right.
    pub(super) fn reserve_lfs(
        &self,
        vault: &oneiron::Vault,
        bytes: u64,
    ) -> oneiron::Result<Option<Reservation>> {
        // Held across the read: an upload that publishes and then returns
        // its reservation is counted once or twice meanwhile, never not at all.
        let mut reserved = self
            .lfs_reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stored = vault.lfs_object_bytes()?;
        if stored.saturating_add(*reserved).saturating_add(bytes) > self.lfs_quota {
            return Ok(None);
        }
        *reserved += bytes;
        Ok(Some(Reservation {
            reserved: Arc::clone(&self.lfs_reserved),
            bytes,
        }))
    }
}

/// Room an upload in flight holds against the LFS quota.
pub(super) struct Reservation {
    reserved: Arc<Mutex<u64>>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        *reserved = reserved.saturating_sub(self.bytes);
    }
}

/// One piece of a request body on its way to the worker; `Ok(None)` is the
/// body's clean end.
pub(super) type BodyPiece = io::Result<Option<Bytes>>;

/// Feeds `body` to the worker in copied pieces of at most `max_piece` bytes,
/// then its clean end. A frame that does not arrive within `idle` ends the
/// body with `TimedOut`; a worker that stopped reading ends the feed quietly.
///
/// Only the wait for the client is timed: a full channel is the worker's
/// backpressure, and the worker bounds its own waits.
pub(super) async fn feed_body(
    body: Body,
    pieces: mpsc::Sender<BodyPiece>,
    idle: Duration,
    max_piece: usize,
) {
    let mut stream = body.into_data_stream();
    loop {
        let frame = match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(None) => {
                let _ = pieces.send(Ok(None)).await;
                return;
            }
            Ok(Some(Err(_))) => {
                let _ = pieces
                    .send(Err(io::Error::other("request body failed")))
                    .await;
                return;
            }
            Err(_) => {
                let _ = pieces
                    .send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body stalled",
                    )))
                    .await;
                return;
            }
        };
        // Copied, never sliced: a slice would keep a hostile giant backing
        // allocation alive for every queued small piece.
        for piece in frame.chunks(max_piece) {
            if pieces
                .send(Ok(Some(Bytes::copy_from_slice(piece))))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// The request body as the worker reads it: what [`feed_body`] sends, up to
/// its clean end. A channel that closes before the clean end is a cancelled
/// body, never a short one.
pub(super) struct BodyReader {
    pieces: mpsc::Receiver<BodyPiece>,
    current: Bytes,
    ended: bool,
}

impl BodyReader {
    pub(super) fn new(pieces: mpsc::Receiver<BodyPiece>) -> Self {
        Self {
            pieces,
            current: Bytes::new(),
            ended: false,
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.current.is_empty() && !self.ended {
            match self.pieces.blocking_recv() {
                Some(Ok(Some(piece))) => self.current = piece,
                Some(Ok(None)) => self.ended = true,
                Some(Err(error)) => return Err(error),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "request body cancelled",
                    ));
                }
            }
        }
        let count = output.len().min(self.current.len());
        output[..count].copy_from_slice(&self.current[..count]);
        self.current = self.current.slice(count..);
        Ok(count)
    }
}

/// Hands one item from the worker to the async side, waiting at most `idle`
/// for room: a response the client stopped reading ends with `TimedOut`, and
/// one whose client went away with `BrokenPipe`.
pub(super) fn send_within<T>(
    runtime: &Handle,
    sender: &mpsc::Sender<T>,
    item: T,
    idle: Duration,
) -> io::Result<()> {
    runtime
        .block_on(sender.send_timeout(item, idle))
        .map_err(|error| match error {
            mpsc::error::SendTimeoutError::Timeout(_) => {
                io::Error::new(io::ErrorKind::TimedOut, "response stalled")
            }
            mpsc::error::SendTimeoutError::Closed(_) => {
                io::Error::new(io::ErrorKind::BrokenPipe, "client went away")
            }
        })
}
