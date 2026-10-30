//! Build/verify runner: durable action-key reservation prevents duplicate dispatch.
use super::*;
use crate::checkout::CheckoutTaskClass;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};

/// In-flight reservation marker preventing duplicate dispatch of the same build/verify action.
/// Key: bytes32 (action key). Value: the id of the run holding it.
const RUNNING_RESERVATION: SideTable<[u8; BUILD_CACHE_ACTION_KEY_LEN], EntityId, Raw> =
    SideTable::new(&side_table::BUILD_CACHE_RUNNING_RESERVATION);

/// One running leg's place: its vault root and action key.
type LegSlot = (PathBuf, [u8; BUILD_CACHE_ACTION_KEY_LEN]);

/// The legs this process is running. The vault writer lease keeps every other process out, so
/// a reservation no entry here holds was left by a crashed or failed run (FIX 9638).
static LIVE_LEGS: LazyLock<Mutex<HashMap<LegSlot, Arc<LiveLeg>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// One running leg, which a second caller of the same action joins (FIX 9941).
struct LiveLeg {
    run: EntityId,
    /// `None` while running; then the captured leg the run made, if any.
    finished: Mutex<Option<Option<CachedBuildLeg>>>,
    woken: Condvar,
}

impl LiveLeg {
    /// Waits for the run to end; the captured leg it made, if any.
    fn join(&self) -> Option<CachedBuildLeg> {
        let mut finished = self.finished.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(captured) = finished.as_ref() {
                return captured.clone();
            }
            finished = self
                .woken
                .wait(finished)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// A run this caller reserved. Dropping it, even in a panic, ends the run for its joiners.
struct ReservedLeg {
    slot: LegSlot,
    live: Arc<LiveLeg>,
    captured: Option<CachedBuildLeg>,
}

impl Drop for ReservedLeg {
    fn drop(&mut self) {
        let mut legs = LIVE_LEGS.lock().unwrap_or_else(PoisonError::into_inner);
        if legs
            .get(&self.slot)
            .is_some_and(|held| Arc::ptr_eq(held, &self.live))
        {
            legs.remove(&self.slot);
        }
        drop(legs);
        *self
            .live
            .finished
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(self.captured.take());
        self.live.woken.notify_all();
    }
}

enum Reservation {
    Cached(CachedActionResult),
    Running(Arc<LiveLeg>),
    Reserved(ReservedLeg),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildLegReceipt {
    pub action_key: ActionKey,
    pub task_class: CheckoutTaskClass,
    pub cache_hit: bool,
    pub producer_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBuildLeg {
    pub cached: CachedActionResult,
    pub receipt: BuildLegReceipt,
    /// False for captured secret-consuming exhaust, which never enters the cache.
    pub reusable: bool,
}
impl BuildCache<'_> {
    /// Only declared-idempotent task classes can use this runner. One run executes an action at
    /// a time: a second caller joins it (FIX 9941), and a crashed or failed run's reservation is
    /// reclaimed by the next call (FIX 9638).
    pub fn run_leg(
        &self,
        class: CheckoutTaskClass,
        action: &BuildAction,
        execute: impl FnOnce(&Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        if !matches!(class, CheckoutTaskClass::Build | CheckoutTaskClass::Verify) {
            return Err(BuildCacheError::InvalidAction(
                "leg is not declared idempotent",
            ));
        }
        let key = action.action_key()?;
        loop {
            if let Some(cached) = self.get(&key)? {
                return Ok(leg(cached, class, true));
            }
            match self.reserve(&key)? {
                Reservation::Cached(cached) => return Ok(leg(cached, class, true)),
                // The run's captured leg, or the cache row or a fresh reservation once it ends.
                Reservation::Running(live) => {
                    if let Some(mut joined) = live.join() {
                        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                        self.admit_account_in_txn(&txn)?;
                        joined.receipt.task_class = class;
                        joined.receipt.cache_hit = true;
                        return Ok(joined);
                    }
                }
                Reservation::Reserved(mut reserved) => {
                    let outcome = self.execute_reserved(class, action, key, execute);
                    // A reservation left by a failed release is reclaimed by the next caller.
                    let _ = self.release_reservation(&key, reserved.live.run);
                    reserved.captured =
                        outcome.as_ref().ok().filter(|done| !done.reusable).cloned();
                    return outcome;
                }
            }
        }
    }

    /// Reserves `key` for one new run, or names the live run holding it. A reservation no live
    /// run holds is taken over under a fresh run id, which fences the run that left it.
    fn reserve(&self, key: &ActionKey) -> BuildCacheResult<Reservation> {
        let slot = (self.vault.store.env.path().to_path_buf(), *key.as_bytes());
        let mut txn = self.vault.store.env.write_txn()?;
        self.admit_account_in_txn(&txn)?;
        if let Some(record) = BUILD_CACHE_REAPI_ROW.get(&self.vault.store, &txn, key.as_bytes())? {
            return Ok(Reservation::Cached(
                self.admit_row_in_txn(&txn, key, record)?,
            ));
        }
        let held = RUNNING_RESERVATION.get_lenient(&self.vault.store, &txn, key.as_bytes())?;
        let mut legs = LIVE_LEGS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(live) = legs.get(&slot).filter(|live| held == Some(live.run)) {
            return Ok(Reservation::Running(Arc::clone(live)));
        }
        let live = Arc::new(LiveLeg {
            run: EntityId::now(),
            finished: Mutex::new(None),
            woken: Condvar::new(),
        });
        RUNNING_RESERVATION.put(&self.vault.store, &mut txn, key.as_bytes(), &live.run)?;
        txn.commit().map_err(Error::from)?;
        legs.insert(slot.clone(), Arc::clone(&live));
        Ok(Reservation::Reserved(ReservedLeg {
            slot,
            live,
            captured: None,
        }))
    }

    /// Drops the reservation `run` holds; a successor that fenced `run` keeps its own.
    fn release_reservation(&self, key: &ActionKey, run: EntityId) -> BuildCacheResult<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        if RUNNING_RESERVATION.get_lenient(&self.vault.store, &txn, key.as_bytes())? == Some(run) {
            RUNNING_RESERVATION.delete(&self.vault.store, &mut txn, key.as_bytes())?;
        }
        txn.commit().map_err(Error::from)?;
        Ok(())
    }

    /// Executes a reserved leg once. A clean result enters the cache; secret-consuming exhaust
    /// is returned as captured artifacts, never as a cache row.
    fn execute_reserved(
        &self,
        class: CheckoutTaskClass,
        action: &BuildAction,
        key: ActionKey,
        execute: impl FnOnce(&Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        let candidate = execute(self.vault)?;
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.admit_account_in_txn(&txn)?;
            let tainted =
                candidate
                    .artifact_refs()
                    .iter()
                    .try_fold(false, |tainted, reference| {
                        match require_clean_in_txn(self.vault, &txn, reference) {
                            Ok(()) => Ok(tainted),
                            Err(BuildCacheError::TaintedResult { .. }) => Ok(true),
                            Err(error) => Err(error),
                        }
                    })?;
            if tainted {
                candidate.validate()?;
                for path in candidate.outputs.keys() {
                    if action.declared_outputs().binary_search(path).is_err() {
                        return Err(BuildCacheError::UndeclaredOutput {
                            path: path.as_str().to_owned(),
                        });
                    }
                }
                let referenced_bytes = inspect_result_in_txn(self.vault, &txn, &candidate, false)?;
                let mut captured = leg(
                    CachedActionResult {
                        action_key: key,
                        action_size_bytes: action.reapi_digest()?.size_bytes,
                        result: candidate,
                        referenced_bytes,
                    },
                    class,
                    false,
                );
                captured.reusable = false;
                return Ok(captured);
            }
        }
        let (cached, hit) = match self.put(action, candidate)? {
            BuildCachePutOutcome::Stored(value) => (value, false),
            BuildCachePutOutcome::Existing(value) => (value, true),
        };
        Ok(leg(cached, class, hit))
    }
}
fn leg(
    cached: CachedActionResult,
    task_class: CheckoutTaskClass,
    cache_hit: bool,
) -> CachedBuildLeg {
    let receipt = BuildLegReceipt {
        action_key: cached.action_key,
        task_class,
        cache_hit,
        producer_ref: cached.result.producer_ref.clone(),
    };
    CachedBuildLeg {
        cached,
        receipt,
        reusable: true,
    }
}
