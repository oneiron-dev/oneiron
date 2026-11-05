//! Retained relationship-scope storage in canonical contact reads.

use crate::Vault;
use crate::claim::ClaimBody;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::host_memory::{MachineMemory, MemoryLease};
use rmpv::Value;
use std::mem::size_of;
use std::ops::Deref;

pub(super) struct ContactClaim {
    body: ClaimBody,
    _memory: Option<MemoryLease>,
}

impl ContactClaim {
    pub(super) fn new(body: ClaimBody, memory: Option<&MachineMemory>) -> Self {
        let memory = memory.map(|memory| {
            let mut lease = memory.empty_lease();
            let bytes = body.rel.as_ref().map_or(0, |ids| {
                (ids.capacity() as u64).saturating_mul(size_of::<EntityId>() as u64)
            });
            lease.materialized(0, bytes);
            lease
        });
        Self {
            body,
            _memory: memory,
        }
    }

    pub(super) fn into_value(self) -> Value {
        self.body.value
    }
}

impl Deref for ContactClaim {
    type Target = ClaimBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

impl Vault {
    /// Reads a contact while accounting for its final claim relationship sets.
    ///
    /// The canonical history selection and decoding finish before the final
    /// retained set is accounted. Intermediate reads and allocations are not
    /// admitted by this method.
    pub fn get_counterparty_contact_with_memory(
        &self,
        id: &EntityId,
        memory: &MachineMemory,
    ) -> Result<Option<CounterpartyContactRecord>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_counterparty_contact_with_memory_in_txn(&rtxn, id, Some(memory))
    }
}
