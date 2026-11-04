//! Per-store clock and id source. No process-global clock or counter.
use crate::error::{Error, Result};
use crate::store::{AfterCommit, DetachedWrite, StoreCore};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
            last_id: Arc::new(Mutex::new(0)),
        }
    }
    /// Fork construction state: sharing the source must not share a vault's floor.
    pub(crate) fn for_store(&self) -> Self {
        let mut clock = Self::new(self.source.clone(), self.ids.clone());
        clock.system = self.system;
        clock
    }
    pub(crate) fn observe_floor(&self, persisted: u64) -> Result<u64> {
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
    pub(crate) fn observe_leased_floor(&self, persisted: u64, lease: u64) -> Result<u64> {
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
    pub(crate) fn leased_now(&self) -> Option<u64> {
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
    pub(crate) fn hold_lease(&self, lease: u64) -> Result<()> {
        let mut known = self
            .lease
            .lock()
            .map_err(|_| Error::InvariantViolation("clock lease lock poisoned"))?;
        *known = (*known).max(lease);
        Ok(())
    }
    /// Takes `now` as the time of an authorization decision made after the
    /// lease lapsed (FIX 12023), never below one this store took before.
    fn judge(&self, now: u64) -> u64 {
        self.judged.fetch_max(now, Ordering::AcqRel).max(now)
    }
    /// The latest time a decision took after the lease lapsed; 0 for none.
    fn judged(&self) -> u64 {
        self.judged.load(Ordering::Acquire)
    }
    /// The renewal of a lapsed lease, when none is queued (FIX 12023):
    /// `None` while another is.
    fn claim_lease_renewal(&self) -> Option<LeaseRenewal> {
        (!self.renewal.swap(true, Ordering::AcqRel)).then(|| LeaseRenewal {
            clock: self.clone(),
        })
    }
    /// The floor this store has observed; 0 when it has observed none.
    fn observed_floor(&self) -> u64 {
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
    pub(crate) fn peek_recorded_at(&self) -> u64 {
        let floor = self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (*floor).max(self.source.now_recorded_at())
    }
    /// The source itself, held at no floor: the host's wall clock. For a
    /// holder proof's signed time, and for a clock that keeps its own
    /// committed floor; never a stamp on what the vault records.
    pub(crate) fn wall_now(&self) -> u64 {
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
        crate::EntityId::from_bytes(source_bytes)?;
        let source = u128::from_be_bytes(source_bytes);
        let next = source.max(
            last.checked_add(1)
                .ok_or(Error::IndexOverflow("id source"))?,
        );
        let bytes = next.to_be_bytes();
        crate::EntityId::from_bytes(bytes)?;
        *last = next;
        Ok(bytes)
    }

    pub fn entity_id(&self) -> Result<crate::EntityId> {
        crate::EntityId::from_bytes(self.ulid()?)
    }

    pub(crate) fn observe_id_floor(&self, persisted: u128) -> Result<u128> {
        let mut last = self
            .last_id
            .lock()
            .map_err(|_| Error::InvariantViolation("id source lock poisoned"))?;
        *last = (*last).max(persisted);
        Ok(*last)
    }
}
impl crate::Vault {
    /// Sample this vault's injected, nondecreasing policy/recording clock.
    pub fn now_recorded_at(&self) -> u64 {
        self.store.clock.now_recorded_at()
    }
    /// Wall milliseconds from this vault's injected clock, held at no
    /// floor: capture-time metadata (FIX 10517).
    pub fn now_recorded_ms(&self) -> u64 {
        self.store.clock.now_recorded_ms()
    }
    /// Allocate an id from this vault's injected source without opening a writer.
    /// A subsequent mutation persists the allocation floor in its transaction.
    pub fn new_entity_id(&self) -> Result<crate::EntityId> {
        self.store.clock.entity_id()
    }
}

/// The stamp a job row takes in a write transaction: the clock floor the
/// vault has committed (another handle on it may have raised it) or this
/// store's clock if later, read without moving either floor.
pub(crate) fn job_recorded_at_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<u64> {
    Ok(authorization_floor_in_txn(store, txn)?.max(store.clock().peek_recorded_at()))
}

/// How far ahead of its observation an authorization decision commits the
/// vault's clock (FIX 11664; Engine 04:02, 5 s): while a store's clock stays
/// under the lease it committed, its reads judge without a write. Recalls
/// come seconds apart, so a shorter lease would still write on almost every
/// one. Past it, they judge without waiting for the writer too, and the
/// lease's renewal is queued (FIX 12023).
pub(crate) const AUTHORIZATION_LEASE_SECS: u64 = 5;

/// The committed clock floor and authorization lease: the floor is the
/// latest time a write or a decision stamped, and the lease bounds every
/// time a decision took without a write (FIX 11664).
fn clock_floor_and_lease_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<(u64, u64)> {
    let Some(bytes) = store.vault_meta().get(txn, CLOCK_FLOOR)? else {
        return Ok((0, 0));
    };
    let half = |at: usize| -> Result<u64> {
        bytes
            .get(at..at + 8)
            .and_then(|part| part.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(Error::CorruptedIndex("recorded clock floor"))
    };
    match bytes.len() {
        8 => Ok((half(0)?, 0)),
        16 => Ok((half(0)?, half(8)?)),
        _ => Err(Error::CorruptedIndex("recorded clock floor")),
    }
}

fn put_clock_floor_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    floor: u64,
    lease: u64,
) -> Result<()> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&floor.to_be_bytes());
    bytes[8..].copy_from_slice(&lease.to_be_bytes());
    store.vault_meta().put(txn, CLOCK_FLOOR, &bytes)?;
    Ok(())
}

/// The time a decision in this authorization snapshot judges at. Callers
/// call `Store::authorization_now` before opening that snapshot. A store
/// that observed the clock judges at what it observed, held between the
/// committed floor and the committed bound: the floor, or the lease when
/// later, or, while a lapsed lease's renewal has not committed, the time of
/// this store's last decision since it lapsed (FIX 12023). So its times stay
/// exact under a lease, never stand above what the vault committed or this
/// store already judged (FIX 11664), and never go back. One that has
/// observed none judges at the committed floor.
pub(crate) fn authorization_floor_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<u64> {
    let (floor, lease) = clock_floor_and_lease_in_txn(store, txn)?;
    let clock = store.clock();
    Ok(match clock.observed_floor() {
        0 => floor,
        observed => observed.clamp(floor, floor.max(lease).max(clock.judged())),
    })
}

impl crate::store::Store {
    /// The time an authorization decision judges at. Call this before
    /// opening the decision's read transaction.
    ///
    /// Under the lease this store committed, the observation is already
    /// bounded by what the vault holds: no write (FIX 11664). Once the lease
    /// has lapsed (FIX 12023, Engine ruling 10-31), the decision judges at
    /// this store's clock now, held at the vault's committed floor and at
    /// every decision this store took before, so it never stands below
    /// either, and it does not wait for the writer: the floor and lease rows
    /// its own writer committed here before are renewed by a detached write,
    /// which commits with the next group after the decision. That write
    /// takes its floor and lease at its stage, from the highest time a
    /// decision took by then, so they cover every decision before it. The
    /// lease is held from its commit, not from its queueing, so it keeps its
    /// 5 s; one renewal is queued at a time, and one that does not commit is
    /// said in a warn and queued again by the next lapsed decision.
    pub(crate) fn authorization_now(&self) -> Result<u64> {
        let clock = crate::store::ManifestDbs::clock(self);
        if let Some(now) = clock.leased_now() {
            return Ok(now);
        }
        // One short snapshot reads the committed floor, and ends before the
        // decision opens its own: it holds no reader slot while a writer is
        // waited for.
        let now = {
            let txn = self.env.read_txn()?;
            let (persisted, lease) = clock_floor_and_lease_in_txn(self, &txn)?;
            clock.observe_leased_floor(persisted, lease)?
        };
        let judged = clock.judge(now);
        if let Some(renewal) = clock.claim_lease_renewal() {
            let staged = Arc::new(AtomicU64::new(0));
            let lease = Arc::clone(&staged);
            self.group_write_detached(
                DetachedWrite::of_core("authorization lease renewal", move |core, txn| {
                    let leased = renew_authorization_lease_in_txn(core, txn)?;
                    lease.store(leased, Ordering::Release);
                    Ok(())
                })
                .replay_only()
                .after_commit(renewal.hold_on_commit(staged)),
            );
        }
        Ok(judged)
    }
}

/// A lapsed lease's queued renewal (FIX 12023). It holds the store's one
/// renewal flag until it drops, so a renewal that committed, failed or was
/// lost lets the next lapsed decision queue another.
struct LeaseRenewal {
    clock: StoreClock,
}

impl LeaseRenewal {
    /// The renewal's after-commit callback: once its group commit is
    /// decided, the lease its stage put in `staged` is held when its rows
    /// landed, and a renewal that did not land is said in a warn. The flag
    /// clears either way, after the hold, so the next lapsed decision queues
    /// a failed renewal again.
    fn hold_on_commit(self, staged: Arc<AtomicU64>) -> AfterCommit {
        Box::new(move |landed| {
            let renewal = self;
            if !landed {
                tracing::warn!(
                    "an authorization lease renewal did not commit; the next lapsed decision queues it again"
                );
            } else if let Err(error) = renewal.clock.hold_lease(staged.load(Ordering::Acquire)) {
                tracing::warn!(%error, "a renewed authorization lease was not held");
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

/// A lapsed lease's renewal, in its group's transaction (FIX 12023): the
/// clock floor and lease rows the decision's own writer committed before,
/// read and observed here, at the stage. Only clock authority: never the
/// floor of ids allocated in RAM but not yet used by a mutation. Returns the
/// lease it commits.
fn renew_authorization_lease_in_txn(core: &StoreCore, txn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let dbs = core.canonical_dbs();
    let (persisted, lease) = clock_floor_and_lease_in_txn(&dbs, txn)?;
    // Never below a time a lapsed decision already took, even past a clock
    // step back, so the lease covers every judged time (L02 10-31).
    let now = core
        .clock
        .observe_leased_floor(persisted, lease)?
        .max(core.clock.judged());
    // A lease another handle committed may already cover it.
    let leased = if lease >= now {
        lease
    } else {
        now.saturating_add(AUTHORIZATION_LEASE_SECS)
    };
    if (now, leased) != (persisted, lease) {
        put_clock_floor_in_txn(&dbs, txn, now, leased)?;
    }
    Ok(leased)
}

pub(crate) const ID_FLOOR: &[u8] = b"ports:id_floor:v1";
pub(crate) const CLOCK_FLOOR: &[u8] = b"ports:clock_floor:v1";
pub(crate) fn recorded_at_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    persist_id_floor_in_txn(store, txn)?;
    observe_clock_floor_in_txn(store, txn)
}

/// This store's clock, observed against the floor the vault has committed,
/// with the observation persisted as the new floor in the caller's
/// transaction. Only the clock floor: the id floor stays where the vault's
/// mutations put it.
pub(crate) fn observe_clock_floor_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let (persisted, lease) = clock_floor_and_lease_in_txn(store, txn)?;
    let now = store.clock().observe_leased_floor(persisted, lease)?;
    if now != persisted {
        put_clock_floor_in_txn(store, txn, now, lease)?;
    }
    Ok(now)
}

/// Persists the floor of the ids this store has allocated, in the caller's
/// transaction, and leaves the clock floor where it is: a write that keeps
/// an allocated id in a row no mutation stamps still keeps that id from
/// being allocated again after a reopen.
pub(crate) fn persist_id_floor_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let id_floor = match store.vault_meta().get(txn, ID_FLOOR)? {
        Some(bytes) => u128::from_be_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("id source floor"))?,
        ),
        None => 0,
    };
    let observed_id_floor = store.clock().observe_id_floor(id_floor)?;
    if observed_id_floor != id_floor {
        store
            .vault_meta()
            .put(txn, ID_FLOOR, &observed_id_floor.to_be_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
