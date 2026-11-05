//! Owner edits of the existing manifest's entity-resolution boundaries.

use serde::{Deserialize, Serialize};

use super::{body_in_txn, invalid, rewrite_default_manifest_field_as_owner_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::gate::entity_resolution_bands::KEY;
use crate::{Error, Result, Vault};

pub use crate::gate::entity_resolution_bands::EntityResolutionBands;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityResolutionBandsConfigureRequest {
    pub expected_body_hash: String,
    pub bands: EntityResolutionBands,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityResolutionBandsView {
    pub manifest_ref: String,
    pub body_hash: String,
    /// The effective trusted-manifest fold, including installed contributions.
    pub bands: EntityResolutionBands,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntityResolutionBandsReceipt {
    pub configuration: EntityResolutionBandsView,
    pub receipt_ref: String,
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityResolutionBandsView> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "entity-resolution bands require an owner-trusted manifest",
        ));
    }
    Ok(EntityResolutionBandsView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(&body).to_hex().to_string(),
        bands: crate::gate::resolve_policy_manifest(&vault.store, txn)?.entity_resolution_bands(),
    })
}

/// Read the effective boundaries and the default manifest's edit precondition.
pub fn entity_resolution_bands_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<EntityResolutionBandsView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// Replace only this row through the native owner writer and receipt ledger.
pub fn configure_entity_resolution_bands_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EntityResolutionBandsConfigureRequest,
) -> Result<EntityResolutionBandsReceipt> {
    if !input.bands.is_finite() {
        return Err(invalid(
            "entity-resolution boundaries must be finite f32 values",
        ));
    }
    let receipt = vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if view(vault, txn)?.body_hash != input.expected_body_hash {
            return Err(invalid(
                "expected_body_hash must match the current policy manifest",
            ));
        }
        let replacement = rmp_serde::to_vec_named(&input.bands)
            .map_err(|_| invalid("entity-resolution bands encoding"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(replacement))
            .map_err(|_| invalid("entity-resolution bands encoding"))?;
        let receipt_ref = rewrite_default_manifest_field_as_owner_in_txn(
            vault,
            owner,
            txn,
            KEY,
            |_| Ok(value),
            "gate.allow.owner_entity_resolution_bands",
        )?;
        Ok(EntityResolutionBandsReceipt {
            configuration: view(vault, txn)?,
            receipt_ref,
        })
    })?;
    vault.apply_pending_rebinds_after_commit();
    Ok(receipt)
}
