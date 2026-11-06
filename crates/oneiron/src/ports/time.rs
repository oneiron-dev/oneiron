//! Per-store clock and id source. No process-global clock or counter.
use crate::error::{Error, Result, StoreError};
use crate::store::{DetachedWrite, StoreCore};
use std::fs::{File, TryLockError};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub(crate) use oneiron_store::store_clock::AUTHORIZATION_LEASE_SECS;
use oneiron_store::store_clock::lease_journal;
pub use oneiron_store::store_clock::{Clock, IdGen, StoreClock};

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
    ///
    /// A time past the committed lease is returned only once the lease
    /// journal holds a bound that covers it, synced off the writer (review
    /// #4484 P1-B; L02 11-04 13:53 = A): a crash before the renewal commits
    /// replays that bound into the floor at the next owned open. When the
    /// journal cannot take it, the decision renews the lease in its writer
    /// first, as before FIX 12023, so its exact time is durable before it is
    /// returned (L02 11-04 15:16). A store whose open did not take the writer
    /// lease keeps no journal and renews in its writer too.
    pub(crate) fn authorization_now(&self) -> Result<u64> {
        let clock = crate::store::ManifestDbs::clock(self);
        if let Some(now) = clock.leased_now() {
            return Ok(now);
        }
        // Past the lease, a decision holds this vault's swap gate shared, in
        // any process, and waits while a restore swap holds it; a handle
        // whose directory a swap moved aside judges nothing past its lease
        // (FIX 12772; REVIEW-5620).
        let _pass = pass_swap_gate(self.canonical_root())?;
        if !self.sits_at_its_path()? {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        let journal = if self.opened_with_writer_lease() {
            clock.lease_journal()
        } else {
            None
        };
        let Some(journal) = journal else {
            return self.renew_authorization_lease_in_writer();
        };
        // One short snapshot reads the committed floor, and ends before the
        // decision opens its own: it holds no reader slot while a writer is
        // waited for.
        let now = {
            let txn = self.env.read_txn()?;
            let (persisted, lease) = clock_floor_and_lease_in_txn(self, &txn)?;
            clock.observe_leased_floor(persisted, lease)?
        };
        if !journal.cover(now) {
            return self.renew_authorization_lease_in_writer();
        }
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
                .after_commit(renewal.hold_on_commit(staged, journal)),
            );
        }
        Ok(judged)
    }

    /// A lapsed lease renewed in this store's own writer before the decision
    /// judges, for a store that keeps no lease journal (its open took no
    /// writer lease) or whose journal failed: the committed floor and lease,
    /// raised past every bound
    /// a lease holder's journal holds, so a crash it left never judges here
    /// below a time it took.
    fn renew_authorization_lease_in_writer(&self) -> Result<u64> {
        let clock = crate::store::ManifestDbs::clock(self);
        // A preliminary read would consume one reader slot per concurrent
        // caller before writers serialize, exhausting small reader budgets.
        // Persist ONLY clock authority here: a read must not also commit the
        // floor of IDs allocated in RAM but not yet used by a mutation.
        let mut txn = self.env.write_txn()?;
        let (persisted, lease) = clock_floor_and_lease_in_txn(self, &txn)?;
        let journaled = lease_journal::journaled_bound(self.canonical_root())?;
        let now = clock.observe_leased_floor(persisted.max(journaled), lease)?;
        // A lease another handle committed may already cover it.
        let leased = if lease >= now {
            lease
        } else {
            now.saturating_add(AUTHORIZATION_LEASE_SECS)
        };
        let changed = (now, leased) != (persisted, lease);
        if changed {
            put_clock_floor_in_txn(self, &mut txn, now, leased)?;
        }
        let id = self.env.info().last_txn_id + 1;
        txn.commit()?;
        clock.hold_lease(leased)?;
        // A floor-only commit changes no Dreamer input (FIX 11568); an empty
        // one moves no txn id and is never noted.
        if changed {
            crate::store::ManifestDbs::diagnostics(self)
                .replay_only_commits
                .note(id);
        }
        Ok(now)
    }

    /// Every open's look at the lease journal before its first decision
    /// (review #4484 Astra P1, 11-04 16:2x): the bound a crashed lease holder
    /// journaled rises into this store's clock floor, so no decision here
    /// judges, under a lease it read, below a time the holder took. A store
    /// whose open took no writer lease reads it again at each renewal.
    pub(crate) fn observe_authorization_lease_journal(&self) -> Result<()> {
        let bound = lease_journal::journaled_bound(self.canonical_root())?;
        if bound > 0 {
            crate::store::ManifestDbs::clock(self).observe_floor(bound)?;
        }
        Ok(())
    }

    /// The owned open's replay of the lease journal (review #4484 P1-B,
    /// condition 3), before any admission: the highest bound a crashed open
    /// journaled commits into the clock floor and this store's clock, then
    /// the journal is emptied for this open's own decisions.
    pub(crate) fn replay_authorization_lease_journal(&self) -> Result<()> {
        let clock = crate::store::ManifestDbs::clock(self);
        let (journal, bound) = lease_journal::replay_at_open(self.canonical_root())?;
        clock.set_lease_journal(Arc::clone(&journal));
        if bound == 0 {
            return Ok(());
        }
        let mut txn = self.env.write_txn()?;
        let (persisted, lease) = clock_floor_and_lease_in_txn(self, &txn)?;
        if bound > persisted {
            put_clock_floor_in_txn(self, &mut txn, bound, lease)?;
            let id = self.env.info().last_txn_id + 1;
            txn.commit()?;
            crate::store::ManifestDbs::diagnostics(self)
                .replay_only_commits
                .note(id);
        } else {
            txn.abort();
        }
        clock.observe_floor(bound)?;
        lease_journal::truncate_after_replay(&journal);
        Ok(())
    }

    /// Closes this vault's authorization decisions past its committed lease
    /// for a restore swap, in every process that holds it open (FIX 12772;
    /// REVIEW-5620): a decision under the lease judges at most the lease and
    /// goes on; one past it waits from now until the returned hold drops,
    /// and those already past it are waited for, up to `deadline`. So the
    /// time the replacement carries, read after this, is past every decision
    /// any handle on this vault takes before the exchange. `None` when those
    /// in flight do not end by `deadline`.
    pub(crate) fn close_authorization_for_swap(
        &self,
        deadline: Instant,
    ) -> Result<Option<AuthorizationSwapHold>> {
        let gate = open_swap_gate(self.canonical_root()).map_err(Error::Io)?;
        loop {
            match gate.try_lock() {
                Ok(()) => return Ok(Some(AuthorizationSwapHold { _gate: gate })),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(SWAP_GATE_POLL);
                }
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(error)) => return Err(Error::Io(error)),
            }
        }
    }

    /// The latest authorization time this vault has committed or may have
    /// taken, read in `txn` under its writer (FIX 12772): its committed clock
    /// floor and lease, the bound its lease journal holds, the latest time
    /// this handle judged or observed, and its clock now. A restore's
    /// replacement carries it before the swap that puts it in this vault's
    /// place ([`Self::carry_authorization_high`]).
    pub(crate) fn authorization_high_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<u64> {
        let (floor, lease) = clock_floor_and_lease_in_txn(self, txn)?;
        let journaled = lease_journal::journaled_bound(self.canonical_root())?;
        let clock = crate::store::ManifestDbs::clock(self);
        Ok(floor
            .max(lease)
            .max(journaled)
            .max(clock.judged())
            .max(clock.observed_floor())
            .max(clock.peek_recorded_at()))
    }

    /// Carries `high`, the latest authorization time of the vault this store
    /// was restored to replace, into this store before the swap (FIX 12772;
    /// REVIEW-4484 Astra R2 P1-3): a bound covering it, `high` plus the
    /// lease, appended and synced in this store's own lease journal, which
    /// its next owned open replays into its committed clock floor, and
    /// observed by this handle's clock now. So the replacement never judges
    /// below a time the vault it replaces took, a wall stepped back
    /// included, and the lease the bound adds covers a decision that vault
    /// takes between this carry and the exchange. A journal that does not
    /// take it refuses, and the swap moves nothing.
    pub(crate) fn carry_authorization_high(&self, high: u64) -> Result<()> {
        let clock = crate::store::ManifestDbs::clock(self);
        let journal = match clock.lease_journal() {
            Some(journal) => journal,
            None => lease_journal::replay_at_open(self.canonical_root())?.0,
        };
        if !journal.cover(high) {
            return Err(Error::InvalidConfig(
                "the replacement's clock lease journal did not take the authorization time of \
                 the vault it replaces; nothing moved, try the swap again"
                    .into(),
            ));
        }
        clock.observe_floor(high)?;
        Ok(())
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

/// The file in a vault's root every handle on it, in any process, locks
/// shared around a decision past the lease, and a restore swap locks
/// exclusively from before it reads the vault's authorization time until its
/// exchange is done (FIX 12772). The lock lives on the open file, so it goes
/// with the handle's close or crash; nothing is registered in memory.
const SWAP_GATE_FILE: &str = "clock-swap.lock";
/// How often a swap looks again for the gate while decisions hold it.
const SWAP_GATE_POLL: Duration = Duration::from_millis(10);

fn open_swap_gate(root: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(root.join(SWAP_GATE_FILE))
}

/// A decision's shared hold on its vault's swap gate, once no swap holds it.
/// A gate that does not open or lock refuses the decision.
fn pass_swap_gate(root: &Path) -> Result<File> {
    let gate = open_swap_gate(root).map_err(Error::Io)?;
    gate.lock_shared().map_err(Error::Io)?;
    Ok(gate)
}

/// A restore swap's exclusive hold on its vault's swap gate: decisions past
/// the lease, in any process, wait until it drops
/// ([`crate::store::Store::close_authorization_for_swap`]).
pub(crate) struct AuthorizationSwapHold {
    _gate: File,
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
