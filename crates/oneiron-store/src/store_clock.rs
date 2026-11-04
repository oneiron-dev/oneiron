//! Per-store clock and id source. No process-global clock or counter.
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod lease_journal;
use lease_journal::LeaseJournal;

/// The engine reads the clock inside the vault's write transaction, which may
/// be one group commit shared with other writes. An implementation must only
/// read time: it must not call into the vault or wait on anything a vault
/// caller can hold while it writes, or the vault's writer deadlocks.
pub trait Clock: Send + Sync {
    fn now_recorded_at(&self) -> u64;
    /// Wall milliseconds for capture-time metadata (FIX 10517): the
    /// source's own time, held at no floor, so a stamp read this way moves
    /// no later write's clock. The default reads seconds.
    fn now_recorded_ms(&self) -> u64 {
        self.now_recorded_at().saturating_mul(1000)
    }
}
/// The engine mints ids inside the vault's write transaction, under the same
/// contract as [`Clock`]: an implementation must only mint ids.
pub trait IdGen: Send + Sync {
    fn ulid(&self) -> [u8; 16];
}
struct SystemClock;
impl Clock for SystemClock {
    fn now_recorded_at(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |v| v.as_secs())
    }
    fn now_recorded_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |v| u64::try_from(v.as_millis()).unwrap_or(u64::MAX))
    }
}
impl IdGen for SystemClock {
    fn ulid(&self) -> [u8; 16] {
        uuid::Uuid::now_v7().into_bytes()
    }
}
#[derive(Clone)]
pub struct StoreClock {
    system: bool,
    source: Arc<dyn Clock>,
    ids: Arc<dyn IdGen>,
    floor: Arc<Mutex<u64>>,
    /// The highest authorization lease this store has read or committed
    /// (FIX 11664); 0 until it first reads one.
    lease: Arc<Mutex<u64>>,
    /// The latest time an authorization decision took after this store's
    /// lease lapsed (FIX 12023); 0 until one does. A decision in a snapshot
    /// read before that lease's renewal commits may stand there.
    judged: Arc<AtomicU64>,
    /// A lapsed lease's renewal is queued and not yet decided (FIX 12023):
    /// one at a time.
    renewal: Arc<AtomicBool>,
    /// The lease journal of this store's owned open (review #4484 P1-B);
    /// `None` for any other open. It closes with the store.
    lease_journal: Arc<Mutex<Option<Arc<LeaseJournal>>>>,
    last_id: Arc<Mutex<u128>>,
}
impl std::fmt::Debug for StoreClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreClock").finish_non_exhaustive()
    }
}
impl PartialEq for StoreClock {
    fn eq(&self, other: &Self) -> bool {
        (self.system && other.system)
            || (Arc::ptr_eq(&self.source, &other.source) && Arc::ptr_eq(&self.ids, &other.ids))
    }
}
impl Default for StoreClock {
    fn default() -> Self {
        let mut clock = Self::new(Arc::new(SystemClock), Arc::new(SystemClock));
        clock.system = true;
        clock
    }
}
impl StoreClock {
    pub fn new(source: Arc<dyn Clock>, ids: Arc<dyn IdGen>) -> Self {
        Self {
            system: false,
            source,
            ids,
            floor: Arc::new(Mutex::new(0)),
            lease: Arc::new(Mutex::new(0)),
            judged: Arc::new(AtomicU64::new(0)),
            renewal: Arc::new(AtomicBool::new(false)),
            lease_journal: Arc::new(Mutex::new(None)),
            last_id: Arc::new(Mutex::new(0)),
        }
    }
    /// Fork construction state: sharing the source must not share a vault's floor.
    pub fn for_store(&self) -> Self {
        let mut clock = Self::new(self.source.clone(), self.ids.clone());
        clock.system = self.system;
        clock
    }
    pub fn observe_floor(&self, persisted: u64) -> Result<u64> {
        let mut floor = self
            .floor
            .lock()
            .map_err(|_| Error::InvariantViolation("clock lock poisoned"))?;
        *floor = (*floor).max(persisted).max(self.source.now_recorded_at());
        Ok(*floor)
    }
    /// [`Self::observe_floor`] against the vault's committed floor and
    /// authorization lease (FIX 11664). The first lease this store reads
    /// raises its floor to it, so after a reopen no decision stands below
    /// one made under that lease before, even when the source rolled back:
    /// for at most [`AUTHORIZATION_LEASE_SECS`], the store's time runs up to
    /// that far ahead.
    pub fn observe_leased_floor(&self, persisted: u64, lease: u64) -> Result<u64> {
        let seed = {
            let mut known = self
                .lease
                .lock()
                .map_err(|_| Error::InvariantViolation("clock lease lock poisoned"))?;
            let seed = if *known == 0 { lease } else { 0 };
            *known = (*known).max(lease);
            seed
        };
        self.observe_floor(persisted.max(seed))
    }
    /// The time an authorization decision takes without a write: this
    /// store's floor observed now, when the lease it holds still covers it
    /// (FIX 11664). `None` when it holds none, or the clock has passed it.
    pub fn leased_now(&self) -> Option<u64> {
        let known = *self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if known == 0 {
            return None;
        }
        let mut floor = self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = (*floor).max(self.source.now_recorded_at());
        if now > known {
            return None;
        }
        *floor = now;
        Some(now)
    }
    /// Holds `lease`, which this store committed.
    pub fn hold_lease(&self, lease: u64) -> Result<()> {
        let mut known = self
            .lease
            .lock()
            .map_err(|_| Error::InvariantViolation("clock lease lock poisoned"))?;
        *known = (*known).max(lease);
        Ok(())
    }
    /// Takes `now` as the time of an authorization decision made after the
    /// lease lapsed (FIX 12023), never below one this store took before.
    pub fn judge(&self, now: u64) -> u64 {
        self.judged.fetch_max(now, Ordering::AcqRel).max(now)
    }
    /// The latest time a decision took after the lease lapsed; 0 for none.
    pub fn judged(&self) -> u64 {
        self.judged.load(Ordering::Acquire)
    }
    /// The renewal of a lapsed lease, when none is queued (FIX 12023):
    /// `None` while another is.
    pub fn claim_lease_renewal(&self) -> Option<LeaseRenewal> {
        (!self.renewal.swap(true, Ordering::AcqRel)).then(|| LeaseRenewal {
            clock: self.clone(),
        })
    }
    /// The lease journal this store's owned open replayed, if any.
    pub fn lease_journal(&self) -> Option<Arc<LeaseJournal>> {
        self.lease_journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    /// Holds `journal` as the lease journal of this store's owned open,
    /// which replayed it.
    pub fn set_lease_journal(&self, journal: Arc<LeaseJournal>) {
        *self
            .lease_journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(journal);
    }
    /// The floor this store has observed; 0 when it has observed none.
    pub fn observed_floor(&self) -> u64 {
        *self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// [`Self::now_recorded_at`] without observing it: the floor stays where
    /// the vault's writes put it, so a stamp read this way (a job row's) moves
    /// no later write's clock, even after the source rolls back.
    ///
    /// The floor stays locked while the source is read, as in
    /// [`Self::now_recorded_at`]: no other caller can observe the clock
    /// between the two reads, so a peek never returns below a floor another
    /// caller saw first.
    pub fn peek_recorded_at(&self) -> u64 {
        let floor = self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (*floor).max(self.source.now_recorded_at())
    }
    /// The source itself, held at no floor: the host's wall clock. For a
    /// holder proof's signed time, and for a clock that keeps its own
    /// committed floor; never a stamp on what the vault records.
    pub fn wall_now(&self) -> u64 {
        self.source.now_recorded_at()
    }
    /// The source's wall milliseconds, held at no floor: capture-time
    /// metadata (FIX 10517); never a stamp on what the vault records.
    pub fn now_recorded_ms(&self) -> u64 {
        self.source.now_recorded_ms()
    }
    /// Nondecreasing seconds, not one fictitious second for each write.
    /// Transactions persist this floor before commit.
    pub fn now_recorded_at(&self) -> u64 {
        let mut floor = self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *floor = (*floor).max(self.source.now_recorded_at());
        *floor
    }
    /// Allocate a store-local identity. Repeated source values never reuse an id,
    /// including two allocations in one transaction or after transaction abort.
    pub fn ulid(&self) -> Result<[u8; 16]> {
        let mut last = self
            .last_id
            .lock()
            .map_err(|_| Error::InvariantViolation("id source lock poisoned"))?;
        let source_bytes = self.ids.ulid();
        EntityId::from_bytes(source_bytes)?;
        let source = u128::from_be_bytes(source_bytes);
        let next = source.max(
            last.checked_add(1)
                .ok_or(Error::IndexOverflow("id source"))?,
        );
        let bytes = next.to_be_bytes();
        EntityId::from_bytes(bytes)?;
        *last = next;
        Ok(bytes)
    }

    pub fn entity_id(&self) -> Result<EntityId> {
        EntityId::from_bytes(self.ulid()?)
    }

    pub fn observe_id_floor(&self, persisted: u128) -> Result<u128> {
        let mut last = self
            .last_id
            .lock()
            .map_err(|_| Error::InvariantViolation("id source lock poisoned"))?;
        *last = (*last).max(persisted);
        Ok(*last)
    }
}

/// How far ahead of its observation an authorization decision commits the
/// vault's clock (FIX 11664; Engine 04:02, 5 s): while a store's clock stays
/// under the lease it committed, its reads judge without a write. Recalls
/// come seconds apart, so a shorter lease would still write on almost every
/// one. Past it, they judge without waiting for the writer too, and the
/// lease's renewal is queued (FIX 12023).
pub const AUTHORIZATION_LEASE_SECS: u64 = 5;

/// A lapsed lease's queued renewal (FIX 12023). It holds the store's one
/// renewal flag until it drops, so a renewal that committed, failed or was
/// lost lets the next lapsed decision queue another.
pub struct LeaseRenewal {
    clock: StoreClock,
}

impl LeaseRenewal {
    /// The renewal's after-commit callback: once its group commit is
    /// decided, the lease its stage put in `staged` is held when its rows
    /// landed, the lease journal is truncated once that lease covers every
    /// bound it holds, and a renewal that did not land is said in a warn.
    /// The flag clears either way, after the hold, so the next lapsed
    /// decision queues a failed renewal again.
    pub fn hold_on_commit(
        self,
        staged: Arc<AtomicU64>,
        journal: Arc<LeaseJournal>,
    ) -> Box<dyn FnOnce(bool) + Send> {
        Box::new(move |landed| {
            let renewal = self;
            if !landed {
                tracing::warn!(
                    "an authorization lease renewal did not commit; the next lapsed decision queues it again"
                );
            } else {
                let leased = staged.load(Ordering::Acquire);
                match renewal.clock.hold_lease(leased) {
                    Ok(()) => journal.settle(leased),
                    Err(error) => {
                        tracing::warn!(%error, "a renewed authorization lease was not held");
                    }
                }
            }
            drop(renewal);
        })
    }
}

impl Drop for LeaseRenewal {
    fn drop(&mut self) {
        self.clock.renewal.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
