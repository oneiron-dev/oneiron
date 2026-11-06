//! The process's physical-memory admission line for host and native work.
//!
//! A lease reserves room before allocation, names materialized bytes once,
//! and returns its remaining charge on drop. Blocking callers use this
//! directly; async callers wait on a blocking worker.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// Physical memory, when the platform says.
pub fn memory_bytes() -> Option<u64> {
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
/// (FIX 7649). The process factory shares one line across server and native callers.
///
/// A lease of `bytes` is admitted when the memory available now (read live,
/// [`crate::limit_ask::available_memory_bytes`]), less the
/// reserve ([`memory_reserve`]) and the pending bytes of every other live
/// lease, still holds them. Leased bytes are pending until their holder
/// names them allocated ([`MemoryLease::materialized`], FIX 8240): the
/// machine's reading already shows those as used, so they are not counted a
/// second time. Where available memory cannot be read, every leased byte,
/// pending or allocated, is counted against the machine's whole memory
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
pub struct MachineMemory {
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
    /// The part of `leased` not yet named allocated.
    pending: u64,
    /// The ticket the next waiter takes.
    next_ticket: u64,
    /// Waiting tickets, the head first: only the head may be admitted.
    waiting: VecDeque<u64>,
}

/// Memory one piece of work holds, admitted by [`MachineMemory::lease`]
/// before the work allocates it. Hold it as long as what it admitted lives;
/// dropping it gives the bytes back and wakes the line.
#[must_use = "a lease gives its memory back as soon as it drops"]
pub struct MemoryLease {
    shared: Arc<MemoryShared>,
    bytes: u64,
    /// The part of `bytes` not yet named allocated.
    pending: u64,
}

/// Why [`MachineMemory::lease`] admitted nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRefusal {
    /// `needed` bytes do not fit even with nothing else leased: past its
    /// reserve the machine has `available` for leases at most.
    Floor { needed: u64, available: u64 },
    /// `needed` bytes did not fit before the deadline, after waiting
    /// `waited` in line.
    WaitedOut { needed: u64, waited: Duration },
}

impl MachineMemory {
    /// The process's shared physical-memory line. Every server and native
    /// boundary in this process takes its leases from this same line.
    pub fn process() -> Self {
        static MEMORY: OnceLock<MachineMemory> = OnceLock::new();
        MEMORY.get_or_init(Self::new).clone()
    }

    /// The machine's memory as the platform reads it, with its reserve.
    fn new() -> Self {
        let total = crate::limit_ask::machine_memory_bytes()
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
    pub fn lease(&self, bytes: u64, deadline: Instant) -> Result<MemoryLease, MemoryRefusal> {
        self.lease_until(bytes, deadline, &|| false)
    }

    /// [`Self::lease`] for work its caller may stop: `stopped` is asked at
    /// each look, and once it says so the wait leaves the line as one that
    /// ran out (FIX 7653), so work whose caller left waits no longer.
    pub fn lease_until(
        &self,
        bytes: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<MemoryLease, MemoryRefusal> {
        self.wait_in_line(bytes, Some(deadline), stopped)
    }

    /// [`Self::lease_until`] with no deadline: on the same line, a wait only
    /// `stopped` ends (FIX 10580).
    pub fn lease_untimed(
        &self,
        bytes: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<MemoryLease, MemoryRefusal> {
        self.wait_in_line(bytes, None, stopped)
    }

    /// The line every lease waits in, until `deadline` when it has one.
    fn wait_in_line(
        &self,
        bytes: u64,
        deadline: Option<Instant>,
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
            let left = deadline.map(|deadline| deadline.saturating_duration_since(now));
            if left.is_some_and(|left| left.is_zero()) || stopped() {
                line.waiting.retain(|waiting| *waiting != ticket);
                shared.changed.notify_all();
                return Err(MemoryRefusal::WaitedOut {
                    needed: bytes,
                    waited: now.saturating_duration_since(started),
                });
            }
            line = shared
                .changed
                .wait_timeout(
                    line,
                    left.map_or(MEMORY_REPOLL, |left| left.min(MEMORY_REPOLL)),
                )
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// A lease of no bytes, taken without waiting: one a holder grows as it
    /// allocates and names allocated what it already read
    /// ([`MemoryLease::materialized`]). It admits nothing itself.
    pub fn empty_lease(&self) -> MemoryLease {
        MemoryLease {
            shared: Arc::clone(&self.shared),
            bytes: 0,
            pending: 0,
        }
    }

    fn admit(&self, line: &mut MemoryLine, bytes: u64) -> MemoryLease {
        line.leased = line.leased.saturating_add(bytes);
        line.pending = line.pending.saturating_add(bytes);
        MemoryLease {
            shared: Arc::clone(&self.shared),
            bytes,
            pending: bytes,
        }
    }
}

impl MemoryShared {
    /// Whether `bytes` more leave the reserve free past every live lease,
    /// measured now: against the memory available, past the leases' pending
    /// bytes, or the machine's whole memory, past every leased byte, where
    /// that cannot be read (FIX 8240).
    fn fits(&self, line: &MemoryLine, bytes: u64) -> bool {
        self.fits_excluding(line, bytes, 0, 0)
    }

    /// Whether `bytes` more fit past every other holder. Growth excludes
    /// only its own pending bytes from the live-reading check, or all its
    /// own bytes when that reading is unavailable; every other lease and
    /// the reserve still count in full. The fallback compares the lease's
    /// whole, its own bytes with the growth, against the machine's memory.
    fn fits_excluding(
        &self,
        line: &MemoryLine,
        bytes: u64,
        own_pending: u64,
        own_leased: u64,
    ) -> bool {
        let whole = own_leased.saturating_add(bytes);
        match crate::limit_ask::available_memory_bytes() {
            Some(available) => {
                available
                    .saturating_sub(self.reserve)
                    .saturating_sub(line.pending.saturating_sub(own_pending))
                    >= bytes
            }
            None => {
                self.total
                    .saturating_sub(self.reserve)
                    .saturating_sub(line.leased.saturating_sub(own_leased))
                    >= whole
            }
        }
    }
}

impl MemoryLease {
    /// The bytes this lease holds.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Checks whether this lease's whole required peak fits on an idle machine.
    /// `pinned` names distinct caller-held input outside this lease; `additional`
    /// is the unreserved growth needed at that peak. Count overlapping input
    /// once, and do not include bytes already held by this lease in either.
    ///
    /// This only checks the floor: it neither reserves nor changes the line.
    /// Pinned input is not added to the shared ledger. Every future allocation
    /// still needs its normal admission, which keeps its existing FIFO wait.
    pub fn check_irreducible_peak(
        &self,
        pinned: u64,
        additional: u64,
    ) -> Result<(), MemoryRefusal> {
        let needed = self.bytes.saturating_add(additional).saturating_add(pinned);
        let available = self.shared.total.saturating_sub(self.shared.reserve);
        if needed > available {
            return Err(MemoryRefusal::Floor { needed, available });
        }
        Ok(())
    }

    /// Grows this lease by `more` bytes on its original line, behind every
    /// waiter already there. The fit check excludes this lease's own bytes,
    /// not any other holder's, so a multi-step allocation cannot wait on its
    /// own earlier reservation. Refused at once when the whole lease would
    /// not fit even with nothing else leased; a refused or stopped growth
    /// leaves this lease and the line's byte counts unchanged.
    pub fn grow(
        &mut self,
        more: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(more, Some(deadline), stopped, self.pending)
    }

    /// Grows a reservation whose earlier bytes may still be unallocated.
    /// Every pending byte stays charged against the live memory reading.
    pub fn grow_pending(
        &mut self,
        more: u64,
        deadline: Instant,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(more, Some(deadline), stopped, 0)
    }

    /// [`Self::grow`] with no deadline: only `stopped` ends the wait.
    pub fn grow_untimed(
        &mut self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(more, None, stopped, self.pending)
    }

    /// [`Self::grow_pending`] without a deadline. Earlier reservations keep
    /// counting until the caller names their allocation with
    /// [`Self::materialized`]; only `stopped` ends the wait.
    pub fn grow_pending_untimed(
        &mut self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(more, None, stopped, 0)
    }

    fn grow_in_line(
        &mut self,
        more: u64,
        deadline: Option<Instant>,
        stopped: &dyn Fn() -> bool,
        own_pending_credit: u64,
    ) -> Result<(), MemoryRefusal> {
        self.check_irreducible_peak(0, more)?;
        let shared = Arc::clone(&self.shared);
        let started = Instant::now();
        let mut line = lock(&shared.line);
        if line.waiting.is_empty()
            && shared.fits_excluding(&line, more, own_pending_credit, self.bytes)
        {
            self.admit_growth(&mut line, more);
            return Ok(());
        }
        let ticket = line.next_ticket;
        line.next_ticket = line.next_ticket.wrapping_add(1);
        line.waiting.push_back(ticket);
        loop {
            if line.waiting.front() == Some(&ticket)
                && shared.fits_excluding(&line, more, own_pending_credit, self.bytes)
            {
                line.waiting.pop_front();
                self.admit_growth(&mut line, more);
                // The next head may fit beside this growth too.
                shared.changed.notify_all();
                return Ok(());
            }
            let now = Instant::now();
            let left = deadline.map(|deadline| deadline.saturating_duration_since(now));
            if left.is_some_and(|left| left.is_zero()) || stopped() {
                line.waiting.retain(|waiting| *waiting != ticket);
                shared.changed.notify_all();
                return Err(MemoryRefusal::WaitedOut {
                    needed: more,
                    waited: now.saturating_duration_since(started),
                });
            }
            line = shared
                .changed
                .wait_timeout(
                    line,
                    left.map_or(MEMORY_REPOLL, |left| left.min(MEMORY_REPOLL)),
                )
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn admit_growth(&mut self, line: &mut MemoryLine, more: u64) {
        line.leased = line.leased.saturating_add(more);
        line.pending = line.pending.saturating_add(more);
        self.bytes = self.bytes.saturating_add(more);
        self.pending = self.pending.saturating_add(more);
    }

    /// Gives back at most `bytes` of this lease and wakes the memory line.
    pub fn shrink(&mut self, bytes: u64) {
        let bytes = bytes.min(self.bytes);
        let pending = bytes.min(self.pending);
        let mut line = lock(&self.shared.line);
        line.leased = line.leased.saturating_sub(bytes);
        line.pending = line.pending.saturating_sub(pending);
        self.bytes -= bytes;
        self.pending -= pending;
        drop(line);
        self.shared.changed.notify_all();
    }

    /// Takes `other`'s bytes into this lease, named allocated (FIX 10589):
    /// the line keeps counting them as leased until this lease drops, and
    /// `other` gives back nothing as it drops. Never waits or refuses.
    pub fn absorb_allocated(&mut self, mut other: MemoryLease) {
        other.materialized(other.pending, other.pending);
        self.bytes = self.bytes.saturating_add(other.bytes);
        other.bytes = 0;
    }

    /// Names `reserved` of this lease's pending bytes allocated, as `actual`
    /// bytes now held (FIX 8240): the lease then holds `actual` in their
    /// place, and the live reading, which shows them as used, is no longer
    /// charged them twice. `(n, n)` names a reservation made; `(estimate,
    /// made)` keeps what was made of an estimate; `(room, 0)` gives back room
    /// left unused; `(0, read)` records bytes read before their size was
    /// known. Never waits or refuses; `reserved` past the lease's pending
    /// bytes counts as all of them.
    pub fn materialized(&mut self, reserved: u64, actual: u64) {
        let reserved = reserved.min(self.pending);
        let mut line = lock(&self.shared.line);
        line.pending = line.pending.saturating_sub(reserved);
        line.leased = line.leased.saturating_sub(reserved).saturating_add(actual);
        self.pending -= reserved;
        self.bytes = self.bytes.saturating_sub(reserved).saturating_add(actual);
        drop(line);
        self.shared.changed.notify_all();
    }
}

impl Drop for MemoryLease {
    fn drop(&mut self) {
        let mut line = lock(&self.shared.line);
        line.leased = line.leased.saturating_sub(self.bytes);
        line.pending = line.pending.saturating_sub(self.pending);
        drop(line);
        self.shared.changed.notify_all();
    }
}

/// The claim count changes in one step under its lock, so a holder that
/// panicked left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
