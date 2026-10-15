//! Bounded transfers between an HTTP body and a blocking worker, shared by
//! the git smart-HTTP and LFS bridges.
//!
//! A transfer takes a permit before its worker starts and the worker holds it
//! (see [`crate::admission`]): past the bound it waits its turn, and is never
//! refused for count. Each side waits on the other for a bounded idle time
//! only: a request body that stops arriving, or a response nobody reads, ends
//! the transfer with `TimedOut` rather than pinning the worker, its child
//! process or its spool for as long as the socket stays open. A transfer that
//! keeps moving, however slowly, is never cut.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::admission::{Admission, Permit, WaitTimedOut};
use crate::config::LimitsConfig;
use crate::machine::DiskFloor;
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// The permits remotely started transfers take, and how long either side of
/// one may wait for the other.
pub(crate) struct Transfers {
    /// One `git http-backend` exchange each, keyed by principal.
    git: Admission<String>,
    /// Each served repository's pushes, one at a time, keyed by its git
    /// common directory. A line lives while a push holds or waits for it.
    pushes: Mutex<HashMap<PathBuf, Arc<Admission<String>>>>,
    /// One LFS upload or download worker each, keyed by principal.
    lfs: Admission<String>,
    /// Bytes past which LFS storage asks whether everything is okay.
    lfs_quota: u64,
    /// Bytes uploads in flight have reserved against `lfs_quota`.
    lfs_reserved: Arc<Mutex<u64>>,
    /// The vault disk's floor, and the room uploads in flight claim on it.
    pub(crate) disk: DiskFloor,
    pub(crate) questions: Arc<LimitQuestions>,
    pub(crate) idle: Duration,
    pub(crate) wait: Duration,
}

impl Transfers {
    /// `vault_dir` is where the vault's spools and stored objects are
    /// written: the disk whose floor holds.
    pub(crate) fn new(
        limits: &LimitsConfig,
        questions: Arc<LimitQuestions>,
        vault_dir: PathBuf,
    ) -> Self {
        let wait = limits.queue_wait();
        Self {
            git: Admission::new(
                LimitRow::GitExchanges,
                Arc::clone(&questions),
                limits.git_exchanges,
                wait,
            ),
            pushes: Mutex::default(),
            lfs: Admission::new(
                LimitRow::LfsTransfers,
                Arc::clone(&questions),
                limits.lfs_transfers,
                wait,
            ),
            lfs_quota: limits.lfs_quota_bytes,
            lfs_reserved: Arc::default(),
            disk: DiskFloor::new(vault_dir, limits.disk_reserve_bytes),
            questions,
            idle: Duration::from_millis(limits.transfer_idle_timeout_ms),
            wait,
        }
    }

    /// A git exchange's permit, at its principal's turn. Callers without a
    /// registered principal share one key.
    pub(super) async fn admit_git(&self, principal: Option<&str>) -> Result<Permit, WaitTimedOut> {
        self.git
            .admit(principal.unwrap_or_default().to_owned())
            .await
    }

    /// A git exchange permit for the host's own repository maintenance. It
    /// waits behind every caller, so it never takes a permit a writer is
    /// waiting for. Blocking: call it from the maintenance worker.
    #[expect(dead_code, reason = "the drop-in for #1456's maintenance worker")]
    pub(crate) fn admit_git_maintenance(&self) -> Result<Permit, WaitTimedOut> {
        self.git.admit_background_blocking()
    }

    /// A push's turn at the repository behind `key`, in its principal's turn
    /// and, within one principal, in arrival order.
    pub(super) async fn push_turn(
        &self,
        key: PathBuf,
        principal: Option<&str>,
    ) -> Result<Permit, WaitTimedOut> {
        let line = {
            let mut pushes = self.pushes.lock().unwrap_or_else(PoisonError::into_inner);
            // A line nobody holds, waits in or is about to join is only this
            // map's: let it go.
            pushes.retain(|_, line| Arc::strong_count(line) > 1 || !line.is_idle());
            Arc::clone(
                pushes
                    .entry(key)
                    .or_insert_with(|| Arc::new(Admission::exclusive(self.wait))),
            )
        };
        line.admit(principal.unwrap_or_default().to_owned()).await
    }

    /// An LFS transfer's permit, keyed as [`Self::admit_git`] is.
    pub(super) async fn admit_lfs(&self, principal: Option<&str>) -> Result<Permit, WaitTimedOut> {
        self.lfs
            .admit(principal.unwrap_or_default().to_owned())
            .await
    }

    /// Reserves `bytes` of the LFS quota for one upload, judged against what
    /// the vault's objects hold now and what other uploads have reserved. An
    /// upload past the quota still lands; the quota row asks. The upload's
    /// worker holds the reservation until it ends, by which time a stored
    /// object counts in its own right.
    ///
    /// It reads every stored object, so it blocks: call it from the blocking
    /// pool, holding the upload's transfer permit.
    pub(super) fn reserve_lfs(
        &self,
        vault: &oneiron::Vault,
        bytes: u64,
    ) -> oneiron::Result<Reservation> {
        let mut reservation = Reservation {
            reserved: Arc::clone(&self.lfs_reserved),
            bytes: 0,
            quota: self.lfs_quota,
            questions: Arc::clone(&self.questions),
        };
        reservation.grow(vault, bytes)?;
        Ok(reservation)
    }
}

/// Room an upload in flight holds against the LFS quota.
pub(super) struct Reservation {
    reserved: Arc<Mutex<u64>>,
    bytes: u64,
    quota: u64,
    questions: Arc<LimitQuestions>,
}

impl Reservation {
    /// Grows the reservation to `bytes` when the upload came to more than
    /// it reserved (one that declared no size reserves the size row), so a
    /// crossing it made on the way still asks. It reads every stored object,
    /// so it blocks; a read that fails leaves the reservation as it was,
    /// and refuses nothing.
    pub(super) fn cover(&mut self, vault: &oneiron::Vault, bytes: u64) {
        if bytes > self.bytes {
            let _ = self.grow(vault, bytes);
        }
    }

    /// Sets the reservation to `bytes`, judged against what the vault's
    /// objects hold and every other reservation.
    fn grow(&mut self, vault: &oneiron::Vault, bytes: u64) -> oneiron::Result<()> {
        // Held across the read: an upload that publishes and then returns
        // its reservation is counted once or twice meanwhile, never not at all.
        let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let stored = vault.lfs_object_bytes()?;
        let others = reserved.saturating_sub(self.bytes);
        let total = stored.saturating_add(others).saturating_add(bytes);
        if total > self.quota {
            self.questions.ask(LimitRow::LfsQuota, self.quota, total);
        }
        *reserved = others.saturating_add(bytes);
        self.bytes = bytes;
        Ok(())
    }
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
            Ok(Some(Err(error))) => {
                let _ = pieces.send(Err(body_failure(error))).await;
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

/// A body that failed, as the worker reads it. A body the listener ended
/// for going quiet is a stall like one this feed times out itself.
fn body_failure(error: axum::Error) -> io::Error {
    let stalled = error
        .into_inner()
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut);
    if stalled {
        io::Error::new(io::ErrorKind::TimedOut, "request body stalled")
    } else {
        io::Error::other("request body failed")
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
