//! The readers that consolidate a claim, and the question each asks first.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::vault::Vault;

pub(crate) use oneiron_store::consolidation_reader::ConsolidationReader;

/// Whether `reader` may consolidate the claim `id`: no owner confirmation of a
/// critical write is outstanding on it
/// ([`super::claim_critical_confirm_settled_in_txn`]). Retrieval never asks.
pub(crate) fn claim_consolidation_eligible_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    reader: ConsolidationReader,
) -> Result<bool> {
    let settled = super::claim_critical_confirm_settled_in_txn(store, txn, id)?;
    if !settled {
        tracing::debug!(
            target: "oneiron::gate",
            reader = reader.code(),
            "a consolidation reader held back a claim awaiting its critical confirm"
        );
    }
    Ok(settled)
}

impl Vault {
    /// [`claim_consolidation_eligible_in_txn`] in its own read transaction,
    /// for a reader that holds none.
    pub(crate) fn claim_consolidation_eligible(
        &self,
        id: &EntityId,
        reader: ConsolidationReader,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        claim_consolidation_eligible_in_txn(&self.store, &txn, id, reader)
    }
}
