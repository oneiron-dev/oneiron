//! Typed owner doors over the resident shares (FIX 11310): set one
//! resident's share of the host-paid allocation, and read every resident's
//! share and depletion. The vault's resident ledger owns every admission
//! rule; these doors only check the owner's proof and project.
use serde::{Deserialize, Serialize};

use super::ResidentShare;
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::run_admission::resident_doors::{
    ResidentShareView, ResidentSharesRequest, ResidentSharesView, SetResidentShareRequest,
};

fn shares_view(vault: &Vault) -> Result<ResidentSharesView> {
    Ok(ResidentSharesView {
        residents: vault
            .resident_shares()?
            .into_iter()
            .map(|read| ResidentShareView {
                resident: read.resident.to_hex(),
                units: read.share.units,
                pinned: read.share.pinned,
                allocation_generation: read.allocation.as_ref().map(|at| at.generation),
                allocation: read.allocation.map(|at| at.id),
                used_units: read.used_units,
                overdraft_units: read.overdraft_units,
                overdrafts: read.overdrafts,
            })
            .collect(),
    })
}

/// Reads every resident's share and depletion.
pub fn resident_shares_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    shares_view(vault)
}

/// Sets one resident's share as the owner asks; its depletion stays as it
/// stands.
pub fn set_resident_share_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    let resident = EntityId::from_hex(&input.resident)
        .map_err(|_| Error::InvalidConfig("resident is not an entity id".to_owned()))?;
    vault.set_resident_share(
        resident,
        ResidentShare {
            units: input.units,
            pinned: input.pinned,
        },
    )?;
    shares_view(vault)
}
