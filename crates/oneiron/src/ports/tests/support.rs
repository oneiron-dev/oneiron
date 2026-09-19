use super::super::memory::{Memory, MemoryWrite, Snapshot};
use super::super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use std::sync::{Arc, Mutex};

pub(super) struct ManualClock {
    now: Mutex<u64>,
    next: Mutex<u64>,
}
impl ManualClock {
    pub(super) fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(now),
            next: Mutex::new(1),
        })
    }
    pub(super) fn set(&self, now: u64) {
        *self.now.lock().unwrap() = now;
    }
    pub(super) fn bundle(self: &Arc<Self>) -> StoreClock {
        StoreClock::new(self.clone(), self.clone())
    }
}
impl Clock for ManualClock {
    fn now_recorded_at(&self) -> u64 {
        *self.now.lock().unwrap()
    }
}
impl IdGen for ManualClock {
    fn ulid(&self) -> [u8; 16] {
        let mut next = self.next.lock().unwrap();
        let mut bytes = [0x71; 16];
        bytes[8..].copy_from_slice(&next.to_be_bytes());
        *next += 1;
        bytes
    }
}
pub(super) trait Backend:
    EntityStore
    + ClaimStore
    + EdgeStore
    + PlaceStore
    + RetrievalIndex
    + ShortIdStore
    + TombstoneStore
    + DependencyIndex
    + ChangeLogStore
    + BlobStore
    + JobQueue
{
    fn read(&self) -> Result<Self::Read<'_>>;
    fn write(&self) -> Result<Self::Write<'_>>;
    fn commit(&self, txn: Self::Write<'_>) -> Result<()>;
    // Fixture-only membership law: production writes this at the witness door.
    fn record_turn_session(
        &self,
        txn: &mut Self::Write<'_>,
        turn: &EntityId,
        session: &EntityId,
    ) -> Result<()>;
}
impl Backend for Vault {
    fn read(&self) -> Result<heed::RoTxn<'_>> {
        Ok(self.store.env.read_txn()?)
    }
    fn write(&self) -> Result<heed::RwTxn<'_>> {
        Ok(self.store.env.write_txn()?)
    }
    fn commit(&self, txn: heed::RwTxn<'_>) -> Result<()> {
        Ok(txn.commit()?)
    }
    fn record_turn_session(
        &self,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        session: &EntityId,
    ) -> Result<()> {
        crate::compaction::record_turn_session_membership_in_txn(
            &self.store,
            txn,
            turn,
            Some(*session),
        )?;
        Ok(())
    }
}
impl Backend for Memory {
    fn read(&self) -> Result<Snapshot> {
        Ok(Memory::read(self))
    }
    fn write(&self) -> Result<MemoryWrite> {
        Ok(Memory::write(self))
    }
    fn commit(&self, txn: MemoryWrite) -> Result<()> {
        Memory::commit(self, txn);
        Ok(())
    }
    fn record_turn_session(
        &self,
        txn: &mut MemoryWrite,
        turn: &EntityId,
        session: &EntityId,
    ) -> Result<()> {
        Memory::record_turn_session(self, txn, *turn, *session);
        Ok(())
    }
}
pub(super) fn fixtures() -> (tempfile::TempDir, Vault, Memory, Arc<ManualClock>) {
    let clock = ManualClock::new(100);
    let mut config = crate::test_util::embedding_test_config();
    config.store_clock = clock.bundle();
    let (temp, vault) = crate::test_util::open_test_vault_with(config);
    // Independent ids/time source, same deterministic input values.
    let memory = Memory::new(ManualClock::new(100).bundle());
    (temp, vault, memory, clock)
}
pub(super) fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}
pub(super) fn row(kind: u8, body: &[u8]) -> EntityRecord {
    EntityRecord {
        entity_type: kind,
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 1,
        body: body.to_vec(),
    }
}
pub(super) fn map(entries: &[(&str, rmpv::Value)]) -> Vec<u8> {
    let value = rmpv::Value::Map(
        entries
            .iter()
            .map(|(k, v)| (rmpv::Value::from(*k), v.clone()))
            .collect(),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).unwrap();
    bytes
}
pub(super) fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = crate::test_util::embedding_test_config();
    config.store_clock = clock.bundle();
    config
}
