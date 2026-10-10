//! One admission budget for every organ: threads, memory, in-flight calls.
//!
//! It decides whether a call may start now, never when work runs (canon
//! pins "no second scheduler"). Classes wait in priority order; background
//! work may hold at most half the threads; one core stays free of organs.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use crate::error::HostError;
use crate::spec::CallClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetConfig {
    pub threads: u32,
    pub memory_bytes: u64,
    pub max_inflight: u32,
}

impl BudgetConfig {
    /// Every core but one, 2 GiB, 64 calls in flight.
    #[must_use]
    pub fn for_this_machine() -> Self {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        Self {
            threads: u32::try_from(cores.saturating_sub(1).max(1)).unwrap_or(1),
            memory_bytes: 2 * 1024 * 1024 * 1024,
            max_inflight: 64,
        }
    }
}

#[derive(Debug, Default)]
struct Used {
    threads: u32,
    memory: u64,
    inflight: u32,
    waiting: [u32; 3],
}

#[derive(Debug)]
pub(crate) struct Budget {
    config: BudgetConfig,
    used: Mutex<Used>,
    freed: Condvar,
}

/// A booked share of the budget, returned on drop.
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    budget: &'a Budget,
    threads: u32,
    memory: u64,
}

fn rank(class: CallClass) -> usize {
    match class {
        CallClass::Interactive => 0,
        CallClass::Agent => 1,
        CallClass::Background => 2,
    }
}

impl Budget {
    pub(crate) fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            used: Mutex::new(Used::default()),
            freed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Used> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Books `threads` and `memory` for one call, waiting in class order
    /// until they fit or `deadline` passes.
    pub(crate) fn admit(
        &self,
        class: CallClass,
        threads: u32,
        memory: u64,
        deadline: Instant,
    ) -> Result<Permit<'_>, HostError> {
        if threads > self.config.threads || memory > self.config.memory_bytes {
            return Err(HostError::OverBudget);
        }
        let rank = rank(class);
        let thread_cap = if class == CallClass::Background {
            (self.config.threads / 2).max(1)
        } else {
            self.config.threads
        };
        let mut used = self.lock();
        used.waiting[rank] += 1;
        loop {
            let ahead = used.waiting[..rank].iter().any(|count| *count > 0);
            let fits = used.threads + threads <= thread_cap
                && used.memory + memory <= self.config.memory_bytes
                && used.inflight < self.config.max_inflight;
            if !ahead && fits {
                used.waiting[rank] -= 1;
                used.threads += threads;
                used.memory += memory;
                used.inflight += 1;
                return Ok(Permit {
                    budget: self,
                    threads,
                    memory,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                used.waiting[rank] -= 1;
                drop(used);
                self.freed.notify_all();
                return Err(HostError::BudgetTimeout);
            }
            used = self
                .freed
                .wait_timeout(used, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut used = self.budget.lock();
        used.threads -= self.threads;
        used.memory -= self.memory;
        used.inflight -= 1;
        drop(used);
        self.budget.freed.notify_all();
    }
}
