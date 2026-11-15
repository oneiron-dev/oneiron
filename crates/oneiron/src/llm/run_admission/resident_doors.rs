//! The typed owner door over the resident shares (FIX 11310): read every
//! resident's share and depletion. The owner sets a share with
//! `vault.settings.set` (key `budget.resident_share`, at the resident's agent
//! scope). The vault's resident ledger owns every admission rule; this door
//! only checks the owner's proof and projects.

use crate::consent::AuthenticatedOwner;
use crate::{Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::run_admission::resident_doors::{
    ResidentShareView, ResidentSharesRequest, ResidentSharesView,
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
