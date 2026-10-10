//! One admission budget for every organ: threads, memory, in-flight calls.
//!
//! It decides whether a call may start now, never when work runs (canon
//! pins "no second scheduler"). Classes wait in priority order; background
//! work may hold at most half the threads; one core stays free of organs.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
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
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    config: BudgetConfig,
    used: Mutex<Used>,
    freed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Used> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn give_back(&self, memory: u64) {
        let mut used = self.lock();
        used.memory -= memory;
        drop(used);
        self.freed.notify_all();
    }
}

/// A booked share of the budget, returned on drop.
#[derive(Debug)]
pub(crate) struct Permit {
    shared: Arc<Shared>,
    threads: u32,
    memory: u64,
}

/// Memory a call's outputs keep after the call returns, out of its permit;
/// given back when the outputs drop.
#[derive(Debug)]
pub(crate) struct Kept {
    shared: Arc<Shared>,
    memory: u64,
}

impl Permit {
    /// Moves up to `bytes` of this permit's memory to outputs that outlive
    /// the call.
    pub(crate) fn keep(&mut self, bytes: u64) -> Kept {
        let memory = bytes.min(self.memory);
        self.memory -= memory;
        Kept {
            shared: Arc::clone(&self.shared),
            memory,
        }
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        self.shared.give_back(self.memory);
    }
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
            shared: Arc::new(Shared {
                config,
                used: Mutex::new(Used::default()),
                freed: Condvar::new(),
            }),
        }
    }

    /// Books `threads` and `memory` for one call, waiting in class order
    /// until they fit or `deadline` passes.
    pub(crate) fn admit(
        &self,
        class: CallClass,
        threads: u32,
        memory: u64,
        deadline: Instant,
    ) -> Result<Permit, HostError> {
        let shared = &self.shared;
        let config = shared.config;
        if threads > config.threads || memory > config.memory_bytes {
            return Err(HostError::OverBudget);
        }
        let rank = rank(class);
        let thread_cap = if class == CallClass::Background {
            (config.threads / 2).max(1)
        } else {
            config.threads
        };
        let mut used = shared.lock();
        used.waiting[rank] += 1;
        loop {
            let ahead = used.waiting[..rank].iter().any(|count| *count > 0);
            let fits = used.threads + threads <= thread_cap
                && used.memory + memory <= config.memory_bytes
                && used.inflight < config.max_inflight;
            if !ahead && fits {
                used.waiting[rank] -= 1;
                used.threads += threads;
                used.memory += memory;
                used.inflight += 1;
                return Ok(Permit {
                    shared: Arc::clone(shared),
                    threads,
                    memory,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                used.waiting[rank] -= 1;
                drop(used);
                shared.freed.notify_all();
                return Err(HostError::BudgetTimeout);
            }
            used = shared
                .freed
                .wait_timeout(used, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut used = self.shared.lock();
        used.threads -= self.threads;
        used.memory -= self.memory;
        used.inflight -= 1;
        drop(used);
        self.shared.freed.notify_all();
    }
}
