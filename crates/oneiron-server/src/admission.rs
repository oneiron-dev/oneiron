//! Finite admission for work a remote caller can start.
//!
//! The rule every remotely reachable piece of work follows: it takes a permit
//! before it begins, it is refused rather than queued when no permit is free,
//! and the permit travels with the work itself (the connection, the child
//! process, the upload spool, the worker thread), never only with the handler
//! that started it. A caller who hangs up therefore frees nothing the work
//! still holds, and a caller who never hangs up holds at most its share.
//!
//! One pool bounds the total and, separately, each key's share of it: a peer
//! address, a principal, a credential.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Which bound refused an admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Saturated {
    /// Every permit in the pool is held.
    Total,
    /// This key holds its whole share.
    PerKey,
}

/// A total bound and a per-key bound over one kind of work.
pub(crate) struct Admission<K> {
    counts: Arc<Mutex<Counts<K>>>,
    total: usize,
    per_key: usize,
}

struct Counts<K> {
    held: usize,
    by_key: HashMap<K, usize>,
}

/// One admitted piece of work. Dropping it returns the permit.
pub(crate) struct Permit<K: Eq + Hash> {
    counts: Arc<Mutex<Counts<K>>>,
    /// `None` for work admitted outside any key's share.
    key: Option<K>,
}

impl<K: Eq + Hash + Clone> Admission<K> {
    /// A pool of `total` permits, of which one key may hold `per_key`.
    pub(crate) fn new(total: usize, per_key: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(Counts {
                held: 0,
                by_key: HashMap::new(),
            })),
            total,
            per_key,
        }
    }

    /// Takes a permit for `key` now, or says which bound is full. Never waits.
    pub(crate) fn try_admit(&self, key: K) -> Result<Permit<K>, Saturated> {
        self.admit(Some(key))
    }

    /// Takes a permit counted against the total only.
    pub(crate) fn try_admit_unkeyed(&self) -> Result<Permit<K>, Saturated> {
        self.admit(None)
    }

    fn admit(&self, key: Option<K>) -> Result<Permit<K>, Saturated> {
        let mut counts = lock(&self.counts);
        if counts.held >= self.total {
            return Err(Saturated::Total);
        }
        if let Some(key) = &key {
            let share = counts.by_key.get(key).copied().unwrap_or(0);
            if share >= self.per_key {
                return Err(Saturated::PerKey);
            }
            counts.by_key.insert(key.clone(), share + 1);
        }
        counts.held += 1;
        Ok(Permit {
            counts: Arc::clone(&self.counts),
            key,
        })
    }
}

impl<K: Eq + Hash> Drop for Permit<K> {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts);
        counts.held = counts.held.saturating_sub(1);
        if let Some(key) = &self.key
            && let Some(share) = counts.by_key.get_mut(key)
        {
            *share = share.saturating_sub(1);
            if *share == 0 {
                counts.by_key.remove(key);
            }
        }
    }
}

/// The counts are plain integers changed in one step each, so a holder that
/// panicked left them whole: a poisoned lock is still a true count.
fn lock<K>(counts: &Mutex<Counts<K>>) -> MutexGuard<'_, Counts<K>> {
    counts.lock().unwrap_or_else(PoisonError::into_inner)
}
