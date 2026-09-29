use super::super::memory::{Memory, MemoryWrite, Snapshot};
use super::super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;

pub(super) trait Backend:
    EntityStore
    + ClaimStore
    + EdgeStore
    + EdgeStoreInventory
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
    /// Fixture-only declaration state, installed before the claim transaction.
    fn set_symbol_lease(
        &self,
        task: EntityId,
        lease: Option<&crate::task_verb::SymbolLease>,
    ) -> Result<()>;
    fn symbol_lease(&self, task: EntityId) -> Result<Option<crate::task_verb::SymbolLease>>;
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
    fn set_symbol_lease(
        &self,
        task: EntityId,
        lease: Option<&crate::task_verb::SymbolLease>,
    ) -> Result<()> {
        let key = [b"tasks.symbol_lease.v1/".as_slice(), task.as_bytes()].concat();
        self.with_write_txn(|txn| {
            if let Some(lease) = lease {
                self.store.vault_meta.put(
                    txn,
                    &key,
                    &serde_json::to_vec(lease)
                        .map_err(|_| crate::Error::InvariantViolation("symbol fixture encoding"))?,
                )?;
            } else {
                self.store.vault_meta.delete(txn, &key)?;
            }
            Ok(())
        })
    }
    fn symbol_lease(&self, task: EntityId) -> Result<Option<crate::task_verb::SymbolLease>> {
        let key = [b"tasks.symbol_lease.v1/".as_slice(), task.as_bytes()].concat();
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|raw| {
                serde_json::from_slice(&raw)
                    .map_err(|_| crate::Error::CorruptedIndex("symbol fixture"))
            })
            .transpose()
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
    fn set_symbol_lease(
        &self,
        task: EntityId,
        lease: Option<&crate::task_verb::SymbolLease>,
    ) -> Result<()> {
        let mut txn = self.write();
        if let Some(lease) = lease {
            Memory::seed_symbol_lease(&mut txn, task, lease.clone());
        } else {
            Memory::remove_symbol_lease(&mut txn, task);
        }
        self.commit(txn);
        Ok(())
    }
    fn symbol_lease(&self, task: EntityId) -> Result<Option<crate::task_verb::SymbolLease>> {
        Ok(self.symbol_lease_for_test(task))
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
