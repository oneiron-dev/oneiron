//! Per-store clock and id source. No process-global clock or counter.
use crate::error::{Error, Result};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    fn now_recorded_at(&self) -> u64;
}
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
    pub fn ulid(&self) -> [u8; 16] {
        self.ids.ulid()
    }
}
pub(crate) const CLOCK_FLOOR: &[u8] = b"ports:clock_floor:v1";
pub(crate) fn recorded_at_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let persisted = match store.vault_meta.get(txn, CLOCK_FLOOR)? {
        Some(bytes) => u64::from_be_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("recorded clock floor"))?,
        ),
        None => 0,
    };
    let now = store.clock.observe_floor(persisted)?;
    store.vault_meta.put(txn, CLOCK_FLOOR, &now.to_be_bytes())?;
    Ok(now)
}
