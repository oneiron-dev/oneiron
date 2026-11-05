//! One existing lease shared with native buffers that can outlive its caller.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::{
    Arc, Instant, MEMORY_REPOLL, MemoryLease, MemoryRefusal, MemoryShared, PoisonError, lock,
};

/// The same lease, with accounting serialized by its machine line's mutex.
/// No account lock is held while admission waits, so another thread may return
/// physically freed buffers to its pending reservation during that wait.
#[derive(Clone)]
pub struct SharedMemoryLease(Arc<SharedLease>);

struct SharedLease {
    machine: Arc<MemoryShared>,
    // All mutations hold machine.line. Atomics allow shared ownership without
    // another lock that a blocking admission would keep from a free callback.
    bytes: AtomicU64,
    pending: AtomicU64,
    assigned: AtomicU64,
    retaining_credit: AtomicBool,
}

impl MemoryLease {
    /// Transfers this lease's existing charge into a shareable account. No new
    /// admission or independent machine line is created.
    pub fn into_shared(mut self) -> SharedMemoryLease {
        let account = SharedMemoryLease(Arc::new(SharedLease {
            machine: Arc::clone(&self.shared),
            bytes: AtomicU64::new(self.bytes),
            pending: AtomicU64::new(self.pending),
            assigned: AtomicU64::new(0),
            retaining_credit: AtomicBool::new(true),
        }));
        self.bytes = 0;
        self.pending = 0;
        account
    }
}

#[derive(Clone, Copy)]
enum Growth {
    More(u64),
    PendingAtLeast(u64),
}

impl Growth {
    fn needed(self, pending: u64) -> u64 {
        match self {
            Self::More(bytes) => bytes,
            Self::PendingAtLeast(bytes) => bytes.saturating_sub(pending),
        }
    }
}

impl SharedMemoryLease {
    /// Grows on the original line, counting all earlier pending reservations.
    /// Only `stopped` ends the wait; a refusal changes no byte counts.
    pub fn grow_pending_untimed(
        &self,
        more: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(Growth::More(more), stopped)
    }

    /// Holds at least `bytes` pending on this account. Buffers physically freed
    /// while admission waits may satisfy the request without any new charge.
    pub fn reserve_pending_untimed(
        &self,
        bytes: u64,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        self.grow_in_line(Growth::PendingAtLeast(bytes), stopped)
    }

    fn grow_in_line(
        &self,
        growth: Growth,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), MemoryRefusal> {
        let machine = &self.0.machine;
        let most = machine.total.saturating_sub(machine.reserve);
        let started = Instant::now();
        let mut line = lock(&machine.line);
        let mut ticket = None;
        loop {
            let own_bytes = self.0.bytes.load(Ordering::Relaxed);
            let pending = self.0.pending.load(Ordering::Relaxed);
            let assigned = self.0.assigned.load(Ordering::Relaxed);
            let more = growth.needed(pending.saturating_sub(assigned));
            let whole = own_bytes.saturating_add(more);
            let head = ticket.map_or(line.waiting.is_empty(), |ticket| {
                line.waiting.front() == Some(&ticket)
            });
            if more == 0
                || (head && whole <= most && machine.fits_excluding(&line, more, 0, own_bytes))
            {
                if let Some(ticket) = ticket {
                    line.waiting.retain(|waiting| *waiting != ticket);
                }
                line.leased = line.leased.saturating_add(more);
                line.pending = line.pending.saturating_add(more);
                self.0.bytes.store(whole, Ordering::Relaxed);
                self.0
                    .pending
                    .store(pending.saturating_add(more), Ordering::Relaxed);
                drop(line);
                machine.changed.notify_all();
                return Ok(());
            }
            let refused = if whole > most {
                Some(MemoryRefusal::Floor {
                    needed: whole,
                    available: most,
                })
            } else if stopped() {
                Some(MemoryRefusal::WaitedOut {
                    needed: more,
                    waited: started.elapsed(),
                })
            } else {
                None
            };
            if let Some(refused) = refused {
                if let Some(ticket) = ticket {
                    line.waiting.retain(|waiting| *waiting != ticket);
                }
                drop(line);
                machine.changed.notify_all();
                return Err(refused);
            }
            if ticket.is_none() {
                let next = line.next_ticket;
                line.next_ticket = next.wrapping_add(1);
                line.waiting.push_back(next);
                ticket = Some(next);
            }
            line = machine
                .changed
                .wait_timeout(line, MEMORY_REPOLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Assigns existing pending room to one native malloc. Does not allocate,
    /// wait for room or join the wait queue; the machine-line lock only
    /// serializes the account with allocation completion and physical frees.
    pub fn try_reserve_pending(&self, bytes: u64) -> bool {
        let _line = lock(&self.0.machine.line);
        if !self.0.retaining_credit.load(Ordering::Relaxed) {
            return false;
        }
        let pending = self.0.pending.load(Ordering::Relaxed);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        if bytes > pending.saturating_sub(assigned) {
            return false;
        }
        self.0
            .assigned
            .store(assigned.saturating_add(bytes), Ordering::Relaxed);
        true
    }

    /// One successfully reserved native malloc now holds its exact request.
    pub fn materialized_reserved(&self, bytes: u64) {
        let mut line = lock(&self.0.machine.line);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let bytes = bytes.min(assigned);
        self.0.assigned.store(assigned - bytes, Ordering::Relaxed);
        self.0.pending.store(pending - bytes, Ordering::Relaxed);
        line.pending = line.pending.saturating_sub(bytes);
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// A successfully reserved malloc failed: its room is still pending and
    /// may be reused. No allocation was named materialized or given back.
    pub fn cancel_reserved(&self, bytes: u64) {
        let mut line = lock(&self.0.machine.line);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        let bytes = bytes.min(assigned);
        self.0.assigned.store(assigned - bytes, Ordering::Relaxed);
        if !self.0.retaining_credit.load(Ordering::Relaxed) {
            let pending = self.0.pending.load(Ordering::Relaxed);
            let held = self.0.bytes.load(Ordering::Relaxed);
            self.0.pending.store(pending - bytes, Ordering::Relaxed);
            self.0.bytes.store(held - bytes, Ordering::Relaxed);
            line.pending = line.pending.saturating_sub(bytes);
            line.leased = line.leased.saturating_sub(bytes);
        }
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// Names pending bytes as physically allocated, as MemoryLease does.
    pub fn materialized(&self, reserved: u64, actual: u64) {
        let mut line = lock(&self.0.machine.line);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        let reserved = reserved.min(pending.saturating_sub(assigned));
        let bytes = self.0.bytes.load(Ordering::Relaxed);
        line.pending = line.pending.saturating_sub(reserved);
        line.leased = line.leased.saturating_sub(reserved).saturating_add(actual);
        self.0.pending.store(pending - reserved, Ordering::Relaxed);
        self.0.bytes.store(
            bytes.saturating_sub(reserved).saturating_add(actual),
            Ordering::Relaxed,
        );
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// Returns physically freed allocation to this same pending reservation.
    /// It admits nothing new and releases no charge, so a replay can reuse the
    /// admission instead of repeatedly losing progress when it aborts.
    pub fn reclaimed(&self, bytes: u64) {
        let mut line = lock(&self.0.machine.line);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let held = self.0.bytes.load(Ordering::Relaxed);
        let bytes = bytes.min(held.saturating_sub(pending));
        if self.0.retaining_credit.load(Ordering::Relaxed) {
            line.pending = line.pending.saturating_add(bytes);
            self.0
                .pending
                .store(pending.saturating_add(bytes), Ordering::Relaxed);
        } else {
            line.leased = line.leased.saturating_sub(bytes);
            self.0.bytes.store(held - bytes, Ordering::Relaxed);
        }
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// The native writer/replay scope has ended. Gives back unused pending
    /// credit now, not when the last cached buffer eventually frees. Actual
    /// buffers stay charged; subsequent physical frees return their charge
    /// instead of retaining more replay credit. Serialized with those frees.
    /// Call after this job's growth waits and writer have returned; no new
    /// growth starts after finish. Per-buffer frees may still run concurrently.
    pub fn finish(&self) {
        let mut line = lock(&self.0.machine.line);
        self.0.retaining_credit.store(false, Ordering::Relaxed);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        let returned = pending.saturating_sub(assigned);
        let held = self.0.bytes.load(Ordering::Relaxed);
        self.0.pending.store(assigned, Ordering::Relaxed);
        self.0.bytes.store(held - returned, Ordering::Relaxed);
        line.pending = line.pending.saturating_sub(returned);
        line.leased = line.leased.saturating_sub(returned);
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// Gives back allocated bytes only, preserving pending credit belonging to
    /// native buffers. Call after those specific allocations are physically free.
    pub fn release_allocated(&self, bytes: u64) {
        let mut line = lock(&self.0.machine.line);
        let held = self.0.bytes.load(Ordering::Relaxed);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let bytes = bytes.min(held.saturating_sub(pending));
        line.leased = line.leased.saturating_sub(bytes);
        self.0.bytes.store(held - bytes, Ordering::Relaxed);
        drop(line);
        self.0.machine.changed.notify_all();
    }

    /// Gives back pending bytes first, matching MemoryLease::shrink. This is
    /// for an allocator's rollback/scratch, not a native physical-free event.
    pub fn shrink(&self, bytes: u64) {
        let mut line = lock(&self.0.machine.line);
        let held = self.0.bytes.load(Ordering::Relaxed);
        let pending = self.0.pending.load(Ordering::Relaxed);
        let assigned = self.0.assigned.load(Ordering::Relaxed);
        let bytes = bytes.min(held.saturating_sub(assigned));
        let returned_pending = bytes.min(pending.saturating_sub(assigned));
        line.leased = line.leased.saturating_sub(bytes);
        line.pending = line.pending.saturating_sub(returned_pending);
        self.0.bytes.store(held - bytes, Ordering::Relaxed);
        self.0
            .pending
            .store(pending - returned_pending, Ordering::Relaxed);
        drop(line);
        self.0.machine.changed.notify_all();
    }
}

impl Drop for SharedLease {
    fn drop(&mut self) {
        let mut line = lock(&self.machine.line);
        line.leased = line.leased.saturating_sub(*self.bytes.get_mut());
        line.pending = line.pending.saturating_sub(*self.pending.get_mut());
        drop(line);
        self.machine.changed.notify_all();
    }
}
