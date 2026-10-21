//! What this machine has: cores, memory, descriptors, free disk. The bounds
//! that are the machine's own (the descriptor floor, the disk floor, the
//! memory work may take, how many code runs fit) are sized from these, never
//! from fleet scale.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Logical cores this process may run on.
pub(crate) fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

/// Physical memory, when the platform says.
pub(crate) fn memory_bytes() -> Option<u64> {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` reads a configuration value and touches no memory
        // of ours.
        let (pages, page) = unsafe {
            (
                libc::sysconf(libc::_SC_PHYS_PAGES),
                libc::sysconf(libc::_SC_PAGESIZE),
            )
        };
        let pages = u64::try_from(pages).ok().filter(|pages| *pages > 0)?;
        let page = u64::try_from(page).ok().filter(|page| *page > 0)?;
        Some(pages.saturating_mul(page))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Descriptors this process may hold open at once, when the platform says.
pub(crate) fn open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct on the stack and nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
            return None;
        }
        if limit.rlim_cur == libc::RLIM_INFINITY {
            return Some(u64::MAX);
        }
        Some(limit.rlim_cur)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The most descriptors serving raises its soft open-file limit to: hard
/// limits are often far higher (524,288 on many Linux hosts; unlimited, as
/// macOS reports it).
const OPEN_FILES_WANTED: u64 = 65_536;

/// Raises this process's soft open-file limit to its hard limit, at most to
/// [`OPEN_FILES_WANTED`], and answers the limit it then holds. A raise the
/// platform refuses keeps the limit there was, and says so.
pub(crate) fn raise_open_file_limit() -> Option<u64> {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct on the stack and nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } == 0 {
            let wanted = limit.rlim_max.min(OPEN_FILES_WANTED);
            if limit.rlim_cur < wanted {
                let raised = libc::rlimit {
                    rlim_cur: wanted,
                    rlim_max: limit.rlim_max,
                };
                // SAFETY: `setrlimit` reads the struct on the stack and nothing else.
                let refused = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const raised) };
                if refused != 0 {
                    tracing::warn!(
                        kind = "open_file_limit",
                        held = limit.rlim_cur,
                        wanted,
                        "the open-file limit was not raised; transfers are bounded by the one held"
                    );
                }
            }
        }
    }
    open_file_limit()
}

/// Bytes an unprivileged writer may still use on the filesystem holding
/// `path`.
pub(crate) fn free_disk_bytes(path: &Path) -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        let stat = rustix::fs::statvfs(path)?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(u64::MAX)
    }
}

/// The disk the vault lives on, the free space it keeps, and the room work in
/// flight has claimed on it. Free space alone is not the floor: two uploads
/// that each see room for one stored copy would both take it, so each claims
/// the bytes it has still to write, and every check counts the others' claims.
/// The owner's backups and rehearsals claim theirs on it too (FIX 5479).
#[derive(Clone, Debug)]
pub(crate) struct DiskFloor {
    dir: PathBuf,
    reserve: u64,
    claimed: Arc<Mutex<u64>>,
    /// The free space a test has the disk show; `None` reads the disk.
    #[cfg(test)]
    shown_free: Arc<Mutex<Option<u64>>>,
}

/// Room one piece of work holds on the disk: bytes it has still to write.
/// Dropping it gives the room back.
pub(crate) struct DiskClaim {
    claimed: Arc<Mutex<u64>>,
    /// Changed only under the floor's lock.
    bytes: AtomicU64,
}

impl DiskFloor {
    pub(crate) fn new(dir: PathBuf, reserve: u64) -> Self {
        Self {
            dir,
            reserve,
            claimed: Arc::default(),
            #[cfg(test)]
            shown_free: Arc::default(),
        }
    }

    /// Has every clone of this floor see `bytes` free on its disk, whatever
    /// the disk holds.
    #[cfg(test)]
    pub(crate) fn show_free(&self, bytes: u64) {
        *lock(&self.shown_free) = Some(bytes);
    }

    /// Whether `bytes` more still leave the reserve free, past every claim.
    pub(crate) fn has_room_for(&self, bytes: u64) -> bool {
        let claimed = lock(&self.claimed);
        self.room(*claimed, bytes)
    }

    /// A claim on no room yet.
    pub(crate) fn claim(&self) -> Arc<DiskClaim> {
        Arc::new(DiskClaim {
            claimed: Arc::clone(&self.claimed),
            bytes: AtomicU64::new(0),
        })
    }

    /// Sets `claim` to `bytes` if they leave the reserve free past every
    /// other claim; a claim that does not fit stays as it was.
    pub(crate) fn hold(&self, claim: &DiskClaim, bytes: u64) -> bool {
        debug_assert!(Arc::ptr_eq(&self.claimed, &claim.claimed));
        let mut claimed = lock(&self.claimed);
        let others = claimed.saturating_sub(claim.bytes.load(Ordering::Relaxed));
        if !self.room(others, bytes) {
            return false;
        }
        *claimed = others.saturating_add(bytes);
        claim.bytes.store(bytes, Ordering::Relaxed);
        true
    }

    /// Whether `path` lies on the disk this floor measures: one filesystem.
    /// A side that cannot be read is taken as another disk, so work landing
    /// there is floored there as well.
    pub(crate) fn measures(&self, path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (std::fs::metadata(&self.dir), std::fs::metadata(path)) {
                (Ok(ours), Ok(theirs)) => ours.dev() == theirs.dev(),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            true
        }
    }

    /// A floor of this one's reserve on the disk `dir` lies on, with no claim
    /// yet: what work that lands there, off this floor's disk, claims on
    /// (FIX 5612). Uploads never claim on it.
    pub(crate) fn on_disk_of(&self, dir: PathBuf) -> Self {
        Self {
            dir,
            reserve: self.reserve,
            claimed: Arc::default(),
            #[cfg(test)]
            shown_free: Arc::clone(&self.shown_free),
        }
    }

    /// A disk that cannot be read is taken as full: a floor that cannot be
    /// checked holds.
    fn room(&self, claimed: u64, bytes: u64) -> bool {
        self.free()
            .is_ok_and(|free| free >= self.reserve.saturating_add(claimed).saturating_add(bytes))
    }

    fn free(&self) -> std::io::Result<u64> {
        #[cfg(test)]
        if let Some(free) = *lock(&self.shown_free) {
            return Ok(free);
        }
        free_disk_bytes(&self.dir)
    }
}

/// What a git exchange holds past memory keeps the reserve uploads keep,
/// counting the room they have claimed.
impl oneiron::origin::smart_http::SpillFloor for DiskFloor {
    fn has_room_for(&self, bytes: u64) -> bool {
        DiskFloor::has_room_for(self, bytes)
    }

    /// `spool` in the directory this floor measures, made on first use, so
    /// the floor guards the disk a spool fills. `None` when it cannot be made.
    fn spool_dir(&self) -> Option<PathBuf> {
        let dir = self.dir.join("spool");
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir).ok()?;
        Some(dir)
    }
}

impl DiskClaim {
    /// The bytes this claim holds now.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

impl Drop for DiskClaim {
    fn drop(&mut self) {
        let mut claimed = lock(&self.claimed);
        *claimed = claimed.saturating_sub(*self.bytes.get_mut());
    }
}

/// What the machine is taken to hold when the platform says nothing of its
/// memory: leases are still counted against it, so work queues for it rather
/// than allocating unaccounted.
const UNREAD_MEMORY_BYTES: u64 = 2 << 30;

/// The least free memory no lease takes, however large the machine.
const MEMORY_RESERVE_FLOOR_BYTES: u64 = 256 << 20;

/// How long a waiter goes between looks at the machine's memory while no
/// lease is given back: memory other work frees is seen within it.
const MEMORY_REPOLL: Duration = Duration::from_millis(200);

/// The free memory every admission leaves untouched on a machine of `total`
/// bytes: the larger of 256 MiB and a sixteenth of it. A floor the machine
/// keeps for everything it does not lease, never a cap on one request.
fn memory_reserve(total: u64) -> u64 {
    (total / 16).max(MEMORY_RESERVE_FLOOR_BYTES)
}

/// The machine's memory, admitted to work before the work allocates it
/// (FIX 7649). One is held per server and its clones share it.
///
/// A lease of `bytes` is admitted when the memory available now (read live,
/// [`oneiron_contracts::limit_ask::available_memory_bytes`]), less the
/// reserve ([`memory_reserve`]) and the bytes of every other live lease,
/// still holds them. A lease whose memory is already allocated is counted
/// twice, once in what the machine reads as used and once as a lease: that
/// only delays admission and never overcommits. Where available memory
/// cannot be read, leases are counted against the machine's whole memory
/// instead; nothing is admitted unaccounted.
///
/// Waiters queue first in, first out: a later request never takes room an
/// earlier one is waiting for. The head re-measures whenever a lease is given
/// back and every [`MEMORY_REPOLL`], until it fits or its deadline passes. A
/// request that cannot fit even on an idle machine (its bytes and the reserve
/// past the machine's memory) is refused at once.
///
/// [`Self::lease`] blocks its thread: a blocking worker calls it directly,
/// and async work calls it inside `spawn_blocking`.
#[derive(Clone)]
pub(crate) struct MachineMemory {
    shared: Arc<MemoryShared>,
}

struct MemoryShared {
    /// The machine's memory: the least of its RAM and its container's limit.
    total: u64,
    /// The free memory no lease takes ([`memory_reserve`]).
    reserve: u64,
    line: Mutex<MemoryLine>,
    /// Woken when a lease is given back or a waiter leaves the line.
    changed: Condvar,
}

/// The leases live now and the requests waiting for room, under one lock.
#[derive(Default)]
struct MemoryLine {
    /// Bytes every live lease holds.
    leased: u64,
    /// The ticket the next waiter takes.
    next_ticket: u64,
    /// Waiting tickets, the head first: only the head may be admitted.
    waiting: VecDeque<u64>,
}

/// Memory one piece of work holds, admitted by [`MachineMemory::lease`]
/// before the work allocates it. Hold it as long as what it admitted lives;
/// dropping it gives the bytes back and wakes the line.
#[must_use = "a lease gives its memory back as soon as it drops"]
pub(crate) struct MemoryLease {
    shared: Arc<MemoryShared>,
    bytes: u64,
}

/// Why [`MachineMemory::lease`] admitted nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryRefusal {
    /// `needed` bytes do not fit even with nothing else leased: past its
    /// reserve the machine has `available` for leases at most.
    Floor { needed: u64, available: u64 },
    /// `needed` bytes did not fit before the deadline, after waiting
    /// `waited` in line.
    WaitedOut { needed: u64, waited: Duration },
}

impl MachineMemory {
    /// The machine's memory as the platform reads it, with its reserve.
    pub(crate) fn new() -> Self {
        let total = oneiron_contracts::limit_ask::machine_memory_bytes()
            .or_else(memory_bytes)
            .unwrap_or(UNREAD_MEMORY_BYTES);
        Self {
            shared: Arc::new(MemoryShared {
                total,
                reserve: memory_reserve(total),
                line: Mutex::default(),
                changed: Condvar::new(),
            }),
        }
    }

    /// A lease of `bytes`, admitted as soon as they fit and the requests
    /// waiting before this one have been admitted or have left; refused at
    /// once when they cannot fit on an idle machine, and when `deadline`
    /// passes first. Blocks the calling thread while it waits.
    pub(crate) fn lease(
        &self,
        bytes: u64,
        deadline: Instant,
    ) -> Result<MemoryLease, MemoryRefusal> {
        self.lease_until(bytes, deadline, &|| false)
    }

    /// [`Self::lease`] for work its caller may stop: `stopped` is asked at
    /// each look, and once it says so the wait leaves the line as one that
    /// ran out (FIX 7653), so work whose caller left waits no longer.
    pub(crate) fn lease_until(
        &self,
        bytes: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<MemoryLease, MemoryRefusal> {
        let shared = &self.shared;
        let most = shared.total.saturating_sub(shared.reserve);
        if bytes > most {
            return Err(MemoryRefusal::Floor {
                needed: bytes,
                available: most,
            });
        }
        let started = Instant::now();
        let mut line = lock(&shared.line);
        if line.waiting.is_empty() && shared.fits(&line, bytes) {
            return Ok(self.admit(&mut line, bytes));
        }
        let ticket = line.next_ticket;
        line.next_ticket = line.next_ticket.wrapping_add(1);
        line.waiting.push_back(ticket);
        loop {
            if line.waiting.front() == Some(&ticket) && shared.fits(&line, bytes) {
                line.waiting.pop_front();
                let lease = self.admit(&mut line, bytes);
                // The next head may fit beside this lease too.
                shared.changed.notify_all();
                return Ok(lease);
            }
            let now = Instant::now();
            let left = deadline.saturating_duration_since(now);
            if left.is_zero() || stopped() {
                line.waiting.retain(|waiting| *waiting != ticket);
                shared.changed.notify_all();
                return Err(MemoryRefusal::WaitedOut {
                    needed: bytes,
                    waited: now.saturating_duration_since(started),
                });
            }
            line = shared
                .changed
                .wait_timeout(line, left.min(MEMORY_REPOLL))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn admit(&self, line: &mut MemoryLine, bytes: u64) -> MemoryLease {
        line.leased = line.leased.saturating_add(bytes);
        MemoryLease {
            shared: Arc::clone(&self.shared),
            bytes,
        }
    }
}

impl MemoryShared {
    /// Whether `bytes` more leave the reserve free past every live lease,
    /// measured now: against the memory available, or the machine's whole
    /// memory where that cannot be read.
    fn fits(&self, line: &MemoryLine, bytes: u64) -> bool {
        oneiron_contracts::limit_ask::available_memory_bytes()
            .unwrap_or(self.total)
            .saturating_sub(self.reserve)
            .saturating_sub(line.leased)
            >= bytes
    }
}

impl MemoryLease {
    /// The bytes this lease holds.
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Grows this lease by `more` bytes, admitted as
    /// [`MachineMemory::lease_until`] admits them (in line, until `deadline`
    /// passes or `stopped` says so), so work that allocates in steps holds
    /// one lease (FIX 7653). Refused at once when the whole lease would not
    /// fit even with nothing else leased; a refused growth leaves the lease
    /// as it was.
    pub(crate) fn grow(
        &mut self,
        more: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        let whole = self.bytes.saturating_add(more);
        let most = self.shared.total.saturating_sub(self.shared.reserve);
        if whole > most {
            return Err(MemoryRefusal::Floor {
                needed: whole,
                available: most,
            });
        }
        let machine = MachineMemory {
            shared: Arc::clone(&self.shared),
        };
        let mut grown = machine.lease_until(more, deadline, stopped)?;
        // The growth's bytes move into this lease; the emptied one gives
        // back nothing as it drops.
        self.bytes = whole;
        grown.bytes = 0;
        Ok(())
    }
}

impl Drop for MemoryLease {
    fn drop(&mut self) {
        let mut line = lock(&self.shared.line);
        line.leased = line.leased.saturating_sub(self.bytes);
        drop(line);
        self.shared.changed.notify_all();
    }
}

/// The machine's memory as the organ host's floor (FIX 7654): an organ's
/// own buffers lease from the same line as every other lease here, within
/// their call's deadline, and leave it when their call is revoked. Each
/// lease is held by the call's room until the call ends.
#[cfg(unix)]
pub(crate) struct OrganFloor(pub(crate) MachineMemory);

#[cfg(unix)]
impl oneiron_organ_host::MachineFloor for OrganFloor {
    fn lease(
        &self,
        bytes: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<Box<dyn Send>, oneiron_organ_host::FloorRefusal> {
        match self.0.lease_until(bytes, deadline, stopped) {
            Ok(lease) => Ok(Box::new(lease)),
            Err(MemoryRefusal::Floor { needed, available }) => {
                Err(oneiron_organ_host::FloorRefusal::Floor { needed, available })
            }
            Err(MemoryRefusal::WaitedOut { .. }) => Err(oneiron_organ_host::FloorRefusal::Deadline),
        }
    }
}

/// The claim count changes in one step under its lock, so a holder that
/// panicked left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
