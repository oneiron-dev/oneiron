//! Canonical contact reads with caller-bound relationship-scope memory.

use crate::Vault;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::entity_id::EntityId;
pub(super) use crate::write_envelope::claim_body::ClaimBodyRead as ContactClaim;
use crate::write_envelope::claim_body::{ClaimBodyReadError, ClaimScopeReadMemory};

impl Vault {
    /// Admits direct canonical relationship backing on the supplied line.
    /// History intermediates remain native; a final projected set is charged
    /// only after its original history selection finishes.
    pub fn get_counterparty_contact_with_memory(
        &self,
        id: &EntityId,
        memory: ClaimScopeReadMemory<'_>,
    ) -> std::result::Result<Option<CounterpartyContactRecord>, ClaimBodyReadError> {
        let rtxn = self.store.env.read_txn().map_err(crate::Error::from)?;
        self.get_counterparty_contact_with_memory_in_txn(&rtxn, id, Some(memory))
    }
}
