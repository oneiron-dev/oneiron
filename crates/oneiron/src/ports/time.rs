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
    /// Allocate an id from this vault's injected source without opening a writer.
    /// A subsequent mutation persists the allocation floor in its transaction.
    pub fn new_entity_id(&self) -> Result<crate::EntityId> {
        self.store.clock.entity_id()
    }
}

pub(crate) const ID_FLOOR: &[u8] = b"ports:id_floor:v1";
pub(crate) const CLOCK_FLOOR: &[u8] = b"ports:clock_floor:v1";
pub(crate) fn recorded_at_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
) -> Result<u64> {
    let persisted = match store.vault_meta().get(txn, CLOCK_FLOOR)? {
        Some(bytes) => u64::from_be_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("recorded clock floor"))?,
        ),
        None => 0,
    };
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
        store.vault_meta().put(txn, ID_FLOOR, &observed_id_floor.to_be_bytes())?;
    }
    let now = store.clock().observe_floor(persisted)?;
    if now != persisted {
        store.vault_meta().put(txn, CLOCK_FLOOR, &now.to_be_bytes())?;
    }
    Ok(now)
}
