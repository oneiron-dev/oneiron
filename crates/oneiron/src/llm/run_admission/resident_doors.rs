//! Typed owner doors over the resident shares (FIX 11310): set one
//! resident's share of the host-paid allocation, and read every resident's
//! share and depletion. The vault's resident ledger owns every admission
//! rule; these doors only check the owner's proof and project.

use super::{AllocationRef, ResidentShare};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::run_admission::resident_doors::{
    ResidentShareView, ResidentSharesRequest, ResidentSharesView, SetResidentShareRequest,
};

/// Each resident's share and its depletion on `allocation`, the one the
/// owner's shares govern (row M2-I: the host account's walletless
/// allocation, `AccountStatus::resident_share_allocation`). `None` shows
/// each resident's newest charged generation.
fn shares_view(vault: &Vault, allocation: Option<&AllocationRef>) -> Result<ResidentSharesView> {
    let reads = match allocation {
        Some(allocation) => vault.resident_shares_on(allocation)?,
        None => vault.resident_shares()?,
    };
    Ok(ResidentSharesView {
        residents: reads
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

/// Reads every resident's share and depletion on `allocation` (see
/// [`shares_view`]).
pub fn resident_shares_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
    allocation: Option<&AllocationRef>,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    shares_view(vault, allocation)
}

/// Sets one resident's share as the owner asks; its depletion stays as it
/// stands. Answers the view on `allocation` (see [`shares_view`]).
pub fn set_resident_share_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
    allocation: Option<&AllocationRef>,
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
    shares_view(vault, allocation)
}
