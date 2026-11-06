//! Capacity custody of immutable row-ID buffers across response owners.

use crate::machine::{MachineMemory, MemoryLease};
use oneiron::EntityId;
use std::fmt;
use std::ops::Deref;

/// The buffer drops before its holder. Every fresh clone owns its own lease.
#[derive(Default)]
pub(crate) struct RetainedRowIds {
    pub(super) ids: Vec<EntityId>,
    pub(super) storage: Option<RetainedRowStorage>,
}

pub(super) struct RetainedRowStorage {
    memory: MachineMemory,
    _lease: MemoryLease,
}

impl RetainedRowIds {
    pub(crate) fn new(ids: Vec<EntityId>, memory: &MachineMemory) -> Self {
        let storage = Some(RetainedRowStorage::new(&ids, memory));
        Self { ids, storage }
    }
}

impl RetainedRowStorage {
    fn new(ids: &Vec<EntityId>, memory: &MachineMemory) -> Self {
        let mut lease = memory.empty_lease();
        lease.materialized(
            0,
            (ids.capacity() as u64).saturating_mul(std::mem::size_of::<EntityId>() as u64),
        );
        Self {
            memory: memory.clone(),
            _lease: lease,
        }
    }
}

impl Clone for RetainedRowIds {
    fn clone(&self) -> Self {
        let ids = self.ids.clone();
        let storage = self
            .storage
            .as_ref()
            .map(|storage| RetainedRowStorage::new(&ids, &storage.memory));
        Self { ids, storage }
    }
}

impl Deref for RetainedRowIds {
    type Target = [EntityId];

    fn deref(&self) -> &Self::Target {
        &self.ids
    }
}

impl fmt::Debug for RetainedRowIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.ids, formatter)
    }
}
