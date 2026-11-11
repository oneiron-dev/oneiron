//! This install's current federation pact statuses (FIX 18595).

use super::FederationPactStatus;
use crate::Vault;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// A local reason a pact does not confer access, beyond its folded status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FederationPactInactiveReason {
    /// The folded scope differs from the signed commitment under the live opening.
    ScopeCommitmentMismatch,
}

/// One pact as this install's current authority view admits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationPactStatusRow {
    /// The pact id, in lowercase hexadecimal.
    pub pact: String,
    /// Activation, suspension or a terminal lifecycle status from the native view.
    pub status: FederationPactStatus,
    /// The pact's current consent epoch.
    pub epoch: u64,
    /// A known local reason; absence does not imply the pact is active.
    pub inactive_reason: Option<FederationPactInactiveReason>,
}

/// All pacts in one read-only authority snapshot, in ascending pact-id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationStatus {
    pub pacts: Vec<FederationPactStatusRow>,
}

impl Vault {
    /// Reads the pacts and their local inactivity reasons from the same snapshot.
    ///
    /// This projects the native authority view, including its existing commitment
    /// check. It neither changes the pacts nor moves the authority clock. Like
    /// [`Self::authority_fold`], this is an embedded vault read; an external door
    /// must admit its caller before exposing the result.
    pub fn federation_status(&self) -> Result<FederationStatus> {
        let txn = self.store.env.read_txn()?;
        self.federation_status_in_txn(&txn)
    }

    /// The owner's status read, revalidated in the snapshot it returns.
    pub fn federation_status_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<FederationStatus> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        self.federation_status_in_txn(&txn)
    }

    fn federation_status_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<FederationStatus> {
        let view = self.authority_view_readonly_in_txn(txn)?;
        let mismatched = view.scope_commitment_mismatches();
        Ok(FederationStatus {
            pacts: view
                .federation_pacts
                .iter()
                .map(|(pact_id, pact)| FederationPactStatusRow {
                    pact: crate::entity_id::bytes_to_hex_lower(pact_id),
                    status: pact.status,
                    epoch: pact.pact_epoch,
                    inactive_reason: mismatched
                        .contains(pact_id)
                        .then_some(FederationPactInactiveReason::ScopeCommitmentMismatch),
                })
                .collect(),
        })
    }
}
