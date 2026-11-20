//! Leaving: the member's half of leaving a company (ARCH-0043
//! #leaving-a-company).

use crate::Vault;
use crate::authority::{AuthorityVaultId, HostSlipIssuer};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::receipt::GuestRevokeOutcome;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;

use super::lookup::inquiry_edge_in_txn;

impl Vault {
    /// Ends every inquiry edge this vault holds to `company_vault_id`,
    /// approved by `owner`, in one writer: the member's half of leaving a
    /// company (ARCH-0043 #leaving-a-company: "The member seat and the
    /// inquiry edge end together"). The company's leave writer ends the seat
    /// and its own half; this ends the member's, so the member's pact is
    /// ended too and its erase requests can be signed. Each edge goes as
    /// [`Self::revoke_inquiry_edge`] revokes one, bound to a pact or not.
    /// Nothing left to end answers an empty list, so a repeat changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// The owner's proof no longer holds; a revoke's own refusals; storage
    /// errors.
    pub fn end_inquiry_edges_with(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        company_vault_id: &AuthorityVaultId,
    ) -> Result<Vec<GuestRevokeOutcome>> {
        let outcomes = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut edges = Vec::new();
            for entry in crate::ports::EntityStoreRead::port_entity_ids_by_type(
                &self.store,
                txn,
                ENTITY_TYPE_FEDERATION_GRANT,
                None,
            )? {
                let grant = entry?;
                if inquiry_edge_in_txn(self, txn, &grant)?
                    .is_some_and(|edge| edge.company_vault_id == *company_vault_id)
                {
                    edges.push(grant);
                }
            }
            edges
                .into_iter()
                .map(|grant| self.revoke_guest_access_in_txn(txn, owner, issuer, grant))
                .collect::<Result<Vec<_>>>()
        })?;
        if outcomes
            .iter()
            .any(|outcome| !outcome.revoked_slips.is_empty())
        {
            self.store.notify_credential_revocations();
        }
        Ok(outcomes)
    }
}
