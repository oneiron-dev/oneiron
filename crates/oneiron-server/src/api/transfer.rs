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

use std::any::Any;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use oneiron::EntityId;
use oneiron::origin::smart_http::ScanBounds;
use oneiron::sync::residence::{
    SEALED_BUNDLE_PUT_PART_MAX, SealedBundleObject, sealed_bundle_stages,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use crate::admission::{Admission, Permit, WaitTimedOut};
use crate::byte_line::{ByteLine, HeldBytes};
use crate::config::LimitsConfig;
use crate::machine::{DiskClaim, DiskFloor};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// The largest page LMDB writes in (`MAX_PAGESIZE`).
const LARGEST_PAGE: u64 = 32 * 1024;

/// The room in memory one chunk exchange takes past its request's decoded
/// selector, and the least either half of the memory row holds: sixteen
/// times the 8 MiB frame it reads whole. Its frame and its decoded request;
/// its manifest's row (within a frame, or it is not read) as read and as the
/// two window docs its selector is judged in hold it, twice each; and its
/// reply, the manifest read again (as stored, decoded and encoded), the
/// chunks it carries and its encoding. Its selector is decoded, and gone,
/// before the manifest is read ([`Transfers::exchange_room`]).
pub(crate) const LFS_MEMORY_ROOM: u64 = 16 * FRAME;

/// The frame a chunk exchange reads whole.
const FRAME: u64 = oneiron::sync::chunks::MAX_CHUNK_SYNC_FRAME as u64;

/// The most a structured body holds decoded, for each byte it takes on the
/// wire, rounded up from what was measured: an LFS install's peak resident
/// bytes past those before it, over its 8 MiB body, with its credential scan
/// on (jobs `measure-1`, `measure-2` and `measure-5`, on the fleet). Random
/// bytes held 5 a byte and JSON at most 70. MessagePack of one value a byte,
/// nested in one-element arrays or maps, held the most, levelling off with
/// depth at about 180 a byte (112 at depth 2, 163 at 8, 178 at 64; the scan
/// refuses deeper nesting). A chunk request's selector is decoded into the
/// same tree of values, which holds less than a scan does.
pub(super) const DECODED_PER_BYTE: u64 = 256;

/// What a download or a verify holds beside its manifest: a chunk as stored
/// and as read, the pieces on their way to the client, and a verify's body,
/// counted generously.
pub(super) const READ_ROOM: u64 = 1024 * 1024;

/// Copies of its manifest's row a download or verify holds at once: the row
/// as read, its body, its references decoded, and their encoding as its id is
/// checked, counted generously.
const MANIFEST_COPIES: u64 = 4;

/// A pair of a read's room in memory and its transfer permit, taken in that
/// order and held together until the read's last byte is handed on.
pub(super) type ReadHold = (HeldBytes, Permit);

/// Descriptors the process keeps whatever its transfers do (the vault's
/// files, the listener, the runtime's own), counted generously.
pub(crate) const OWN_DESCRIPTORS: u64 = 256;

/// Descriptors one git exchange may hold at its peak, counted generously:
/// its backend's three pipes, the repository lock file, and, while the
/// backend still writes, a git child the exchange reads through (an
/// advertisement's object checks, a push's door) with its three pipes open
/// as the next one starts, both ends of that one's three pipes and of its
/// exec-error channel.
pub(crate) const GIT_DESCRIPTORS: u64 = 16;

/// Descriptors one LFS transfer holds: an upload's spool.
const LFS_DESCRIPTORS: u64 = 1;

/// Copies of a sealed bundle upload's object the home's disk holds at once
/// (CALLS: SEALED_BUNDLE_DISK_COPY_COUNT): its stage, and the stored copy its
/// commit or replace writes before the stage goes (FIX 3354).
const SEALED_BUNDLE_DISK_COPY_COUNT: u64 = 2;

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
    /// LFS reads' room in memory, half the memory row: a chunk exchange's
    /// [`LFS_MEMORY_ROOM`], or what a download's or a verify's manifest
    /// takes ([`Self::read_room`]). A read takes it before its transfer
    /// permit (the lock order [`crate::byte_line`] names). The origin's
    /// checks that published refs' LFS objects are readable take theirs on
    /// it too ([`OriginReads`]).
    lfs_reads: Arc<ByteLine>,
    /// Uploads' room in memory to install, the other half (by
    /// `git_lfs::streaming::install_room`). A worker takes it once its body
    /// is spooled, holding its transfer permit, so it is held only for
    /// server-side work, never while a client sends.
    lfs_installs: Arc<ByteLine>,
    /// Bytes past which LFS storage asks whether everything is okay.
    lfs_quota: u64,
    /// Bytes uploads in flight have reserved against `lfs_quota`.
    lfs_reserved: Arc<Mutex<u64>>,
    /// The vault disk's floor, and the room uploads in flight claim on it.
    /// What a git exchange holds past memory keeps it too.
    pub(crate) disk: DiskFloor,
    /// The room each sealed bundle upload the home stages claims on `disk`,
    /// by its machine and object: held across its parts, through the commit
    /// or replace that writes its stored copy (FIX 3354).
    sealed_stages: Mutex<HashMap<(EntityId, SealedBundleObject), Arc<DiskClaim>>>,
    /// The page size the vault's object plane is stored in, which each
    /// stored chunk rounds up to; the largest LMDB writes in when it cannot
    /// be read.
    lfs_page: u64,
    /// The page size a test has the object plane look stored in.
    #[cfg(test)]
    shown_page: Mutex<Option<u64>>,
    pub(crate) questions: Arc<LimitQuestions>,
    pub(crate) idle: Duration,
    /// Bytes of one push's status report held in memory while its landing is
    /// journaled; the rest is held on disk, above `disk`'s reserve.
    pub(crate) git_status_memory: usize,
    /// The floors a push's door scan keeps.
    pub(crate) scan: ScanBounds,
    pub(crate) wait: Duration,
}

/// Bytes of one push's status report held in memory: a 512th of the
/// machine's memory, 8 MiB when that cannot be read. A push holds two such
/// copies at most, the report and its rewrite, and only its exchange's worker
/// holds them, under the exchange's permit until the report is sent; so every
/// git exchange holding both at once keeps to a small share of memory.
fn git_status_memory() -> usize {
    crate::machine::memory_bytes().map_or(8 * 1024 * 1024, |bytes| {
        usize::try_from(bytes / 512).unwrap_or(usize::MAX)
    })
}

impl Transfers {
    /// The floor holds on the disk `vault` writes its spools and stored
    /// objects to.
    pub(crate) fn new(
        limits: &LimitsConfig,
        questions: Arc<LimitQuestions>,
        vault: &oneiron::Vault,
    ) -> oneiron::Result<Self> {
        let wait = limits.queue_wait();
        let half = usize::try_from(limits.lfs_memory_bytes / 2).unwrap_or(usize::MAX);
        let open_files = crate::machine::raise_open_file_limit();
        let (git, lfs) = descriptor_bounds(limits, open_files);
        tracing::info!(
            kind = "transfer_descriptor_room",
            open_files = ?open_files,
            git_exchanges = git,
            lfs_transfers = lfs,
            "transfers are bounded by the open-file limit the process holds"
        );
        if git < limits.git_exchanges || lfs < limits.lfs_transfers {
            tracing::warn!(
                kind = "transfer_descriptor_room",
                git_exchanges = git,
                lfs_transfers = lfs,
                "the open-file limit leaves room for fewer transfers than their rows; past it they queue"
            );
        }
        let lfs_reads = Arc::new(ByteLine::new(LimitRow::LfsMemoryBytes, half));
        OriginReads::lend(vault, &lfs_reads, &questions, wait);
        let transfers = Self {
            git: Admission::new(LimitRow::GitExchanges, Arc::clone(&questions), git, wait),
            pushes: Mutex::default(),
            lfs: Admission::new(LimitRow::LfsTransfers, Arc::clone(&questions), lfs, wait),
            lfs_reads,
            lfs_installs: Arc::new(ByteLine::new(LimitRow::LfsMemoryBytes, half)),
            lfs_quota: limits.lfs_quota_bytes,
            lfs_reserved: Arc::default(),
            disk: DiskFloor::new(
                vault.lfs_storage_dir().to_owned(),
                limits.disk_reserve_bytes,
            ),
            sealed_stages: Mutex::default(),
            lfs_page: vault.lfs_storage_page_size().unwrap_or(LARGEST_PAGE),
            #[cfg(test)]
            shown_page: Mutex::default(),
            questions,
            idle: Duration::from_millis(limits.transfer_idle_timeout_ms),
            git_status_memory: git_status_memory(),
            scan: limits.scan_bounds()?,
            wait,
        };
        // An upload staged before this start claims the rest it takes.
        transfers.reconcile_sealed_stages(vault);
        Ok(transfers)
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

    /// The page size the vault's object plane is stored in.
    pub(super) fn lfs_page(&self) -> u64 {
        #[cfg(test)]
        if let Some(page) = *self
            .shown_page
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            return page;
        }
        self.lfs_page
    }

    /// Has the object plane look stored in `page`-byte pages, whatever the
    /// vault's are.
    #[cfg(test)]
    pub(crate) fn show_page(&self, page: u64) {
        *self
            .shown_page
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(page);
    }

    /// The room a sealed bundle upload of a `total`-byte object, `staged`
    /// bytes in, still takes on the disk: [`SEALED_BUNDLE_DISK_COPY_COUNT`]
    /// copies of the object, each in parts of at most
    /// [`SEALED_BUNDLE_PUT_PART_MAX`] that take at most a page more than their
    /// bytes once rounded up to whole pages, less the stage written so far.
    fn sealed_stage_room(&self, total: u64, staged: u64) -> u64 {
        let page = self.lfs_page();
        let on_disk = |bytes: u64| {
            bytes.saturating_add(
                bytes
                    .div_ceil(SEALED_BUNDLE_PUT_PART_MAX as u64)
                    .saturating_mul(page),
            )
        };
        on_disk(total)
            .saturating_mul(SEALED_BUNDLE_DISK_COPY_COUNT)
            .saturating_sub(on_disk(staged))
    }

    /// Claims the room `machine`'s upload of `object` still takes before its
    /// next part, `staged` bytes of `total` in (FIX 3354). The claim stays
    /// with the stage across its parts; hold the one returned until the part
    /// is staged. `None` when that room would cross the disk's floor.
    pub(crate) fn hold_sealed_stage(
        &self,
        machine: EntityId,
        object: SealedBundleObject,
        total: u64,
        staged: u64,
    ) -> Option<Arc<DiskClaim>> {
        let claim = Arc::clone(
            self.sealed_stages
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry((machine, object))
                .or_insert_with(|| self.disk.claim()),
        );
        self.disk
            .hold(&claim, self.sealed_stage_room(total, staged))
            .then_some(claim)
    }

    /// Sets each sealed bundle upload's claim to the rest its stage header in
    /// `vault` says it takes: a stage committed, replaced or idled out gives
    /// its room back, and one staged before a restart claims its rest again.
    /// A claim a part still holds stays until that part is staged.
    pub(crate) fn reconcile_sealed_stages(&self, vault: &oneiron::Vault) {
        let Ok(stages) = sealed_bundle_stages(vault) else {
            return;
        };
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        claims.retain(|key, claim| {
            Arc::strong_count(claim) > 1
                || stages
                    .iter()
                    .any(|stage| (stage.machine, stage.object) == *key)
        });
        for stage in stages {
            let claim = claims
                .entry((stage.machine, stage.object))
                .or_insert_with(|| self.disk.claim());
            // A rest that no longer fits keeps the claim it had.
            self.disk
                .hold(claim, self.sealed_stage_room(stage.total, stage.staged));
        }
    }

    /// An LFS transfer's permit, keyed as [`Self::admit_git`] is.
    pub(super) async fn admit_lfs(&self, principal: Option<&str>) -> Result<Permit, WaitTimedOut> {
        self.lfs
            .admit(principal.unwrap_or_default().to_owned())
            .await
    }

    /// Room in memory for one LFS read of `bytes`, at its turn: reads wait
    /// in arrival order, each up to the queue deadline, and one larger than
    /// the half waits to run alone. Take it before the read's transfer
    /// permit, so a read waiting for room holds no permit an upload could
    /// use. `None` when the wait ran out.
    pub(super) async fn lfs_read_room(&self, bytes: u64) -> Option<HeldBytes> {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        self.lfs_reads
            .reserve_alone(bytes, self.wait, &self.questions)
            .await
    }

    /// The room a chunk exchange whose request declares `declared` bytes
    /// takes: [`LFS_MEMORY_ROOM`], and its request decoded, by the bytes it
    /// may read ([`DECODED_PER_BYTE`] each, a frame's when it declares no
    /// length). It reads no more than it declared.
    pub(super) fn exchange_room(declared: Option<u64>) -> u64 {
        let request = declared.map_or(FRAME, |declared| declared.min(FRAME));
        LFS_MEMORY_ROOM.saturating_add(request.saturating_mul(DECODED_PER_BYTE))
    }

    /// The room a download or a verify of `oid` takes: its manifest's row,
    /// read in place, as many times as it is copied at once, and the chunk
    /// and pieces beside it ([`READ_ROOM`]). `None` when no live object has
    /// the id: a read sized so reads no manifest, even one that lands while
    /// it waits.
    pub(super) fn read_room(
        vault: &oneiron::Vault,
        oid: oneiron::origin::lfs::LfsOid,
    ) -> oneiron::Result<Option<u64>> {
        Ok(vault.lfs_manifest_row_bytes(oid)?.map(manifest_room))
    }

    /// The line an upload's worker takes its install room on, once its body
    /// is spooled. Reads and installs take their room on different halves,
    /// so an upload holding its transfer permit while it waits never waits
    /// on a read that waits for a transfer permit.
    pub(super) fn lfs_installs(&self) -> Arc<ByteLine> {
        Arc::clone(&self.lfs_installs)
    }

    /// The line LFS reads take their room on.
    #[cfg(test)]
    pub(crate) fn lfs_reads(&self) -> &ByteLine {
        &self.lfs_reads
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

/// The git and LFS bounds the open-file limit leaves room for once the
/// sockets (`max_connections`) and the process's own descriptors are counted:
/// half of what is left for each, and never more than its row. Past either,
/// transfers queue as they do past the row, so admitted work never opens
/// more descriptors than the process has.
fn descriptor_bounds(limits: &LimitsConfig, open_files: Option<u64>) -> (usize, usize) {
    let Some(open_files) = open_files else {
        return (limits.git_exchanges, limits.lfs_transfers);
    };
    let room = open_files
        .saturating_sub(limits.max_connections as u64)
        .saturating_sub(OWN_DESCRIPTORS)
        / 2;
    let bound = |row: usize, each: u64| {
        usize::try_from(room / each)
            .unwrap_or(usize::MAX)
            .min(row)
            .max(1)
    };
    (
        bound(limits.git_exchanges, GIT_DESCRIPTORS),
        bound(limits.lfs_transfers, LFS_DESCRIPTORS),
    )
}

/// The room reading a whole manifest whose row is `row` bytes takes: the row
/// as many times as it is copied at once, and the chunk and pieces beside it.
fn manifest_room(row: u64) -> u64 {
    row.saturating_mul(MANIFEST_COPIES)
        .saturating_add(READ_ROOM)
}

/// The reads line, lent to the origin's checks that published refs' LFS
/// objects are readable: each whole manifest they read waits for room on it
/// as a download's does. They run on git exchange workers, which hold their
/// permit and may hold the repository, so the lock order is git permit,
/// repository, reads line; no read holding room waits for either.
struct OriginReads {
    reads: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
    wait: Duration,
}

impl OriginReads {
    fn lend(
        vault: &oneiron::Vault,
        reads: &Arc<ByteLine>,
        questions: &Arc<LimitQuestions>,
        wait: Duration,
    ) {
        vault.set_lfs_read_room(Arc::new(Self {
            reads: Arc::clone(reads),
            questions: Arc::clone(questions),
            wait,
        }));
    }
}

impl oneiron::origin::lfs::LfsReadRoom for OriginReads {
    fn hold(&self, row_bytes: u64) -> Option<Box<dyn Any + Send>> {
        let bytes = usize::try_from(manifest_room(row_bytes)).unwrap_or(usize::MAX);
        // The check runs on a thread that may block (a transfer worker, or
        // the blocking pool), whether or not the server was built on a
        // runtime: its wait runs on a timer of its own.
        let timer = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .ok()?;
        timer
            .block_on(self.reads.reserve_alone(bytes, self.wait, &self.questions))
            .map(|held| Box::new(held) as Box<dyn Any + Send>)
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

/// A worker that ended without an answer: it panicked, or its thread never
/// started.
pub(super) type WorkerGone = tokio::sync::oneshot::error::RecvError;

/// Runs a transfer's `work` on a thread of its own and answers when it ends.
///
/// Never the runtime's shared blocking pool: a transfer works for as long as
/// its body keeps moving and the transfer rows admit thousands, so on that
/// pool (512 threads) one credential's slow transfers could hold every thread
/// the rest of the server needs, and work behind them would wait in the
/// pool's own line, with no deadline and no turns. Each worker holds its
/// permit, so the rows bound these threads.
pub(super) fn spawn_worker<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> tokio::sync::oneshot::Receiver<T> {
    let (answer, answered) = tokio::sync::oneshot::channel();
    // A thread that cannot start drops `work`, and with it the permit; the
    // caller reads a worker that ended without an answer.
    if let Err(error) = std::thread::Builder::new()
        .name("transfer-worker".to_owned())
        .spawn(move || {
            let _ = answer.send(work());
        })
    {
        tracing::warn!(kind = ?error.kind(), "a transfer worker thread did not start");
    }
    answered
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
