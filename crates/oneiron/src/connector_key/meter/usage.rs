//! Identity and lifecycle of one native effector usage debit.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::connector_key) struct UsageEntry {
    pub(super) id: EntityId,
    pub(super) at: u64,
    pub(super) amount: u64,
    pub(super) reserved: bool,
}

impl UsageEntry {
    pub(in crate::connector_key) fn settled(
        store: &Store,
        wtxn: &mut heed::RwTxn<'_>,
        at: u64,
        amount: u64,
    ) -> Result<Self> {
        let id = store.clock.entity_id()?;
        // Usage rows have no entity write to persist their allocated id.
        crate::ports::persist_id_floor_in_txn(store, wtxn)?;
        Ok(Self {
            id,
            at,
            amount,
            reserved: false,
        })
    }
}
