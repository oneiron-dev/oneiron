//! Canonical contact value reads with caller-bound memory custody.

use crate::Vault;
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::entity_id::EntityId;
pub(super) use crate::write_envelope::claim_body::ClaimValueHead as ContactClaim;
use crate::write_envelope::claim_body::{ClaimBodyReadError, ClaimScopeReadMemory};

impl Vault {
    /// Retains canonical head values on the supplied line without materializing
    /// unused relationship sets. History intermediates remain native.
    pub fn get_counterparty_contact_with_memory(
        &self,
        id: &EntityId,
        memory: ClaimScopeReadMemory<'_>,
    ) -> std::result::Result<Option<CounterpartyContactRecord>, ClaimBodyReadError> {
        let rtxn = self.store.env.read_txn().map_err(crate::Error::from)?;
        self.get_counterparty_contact_with_memory_in_txn(&rtxn, id, Some(memory))
    }
}
