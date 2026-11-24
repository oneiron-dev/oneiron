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

/// Which depletion a share view shows beside each resident's setting.
#[derive(Clone, Copy)]
enum Depletion<'a> {
    /// Each resident's newest charged generation: the embedded verb rows,
    /// whose vault has no host account to name the allocation.
    NewestGeneration,
    /// The allocation the owner's shares govern (row M2-I: the host
    /// account's walletless allocation,
    /// `AccountStatus::resident_share_allocation`). `None` when the account
    /// selects no walletless allocation: the shares then govern nothing, and
    /// the view shows the settings with no depletion, never another
    /// wallet's usage (review 10403 P1-2).
    On(Option<&'a AllocationRef>),
}

/// Each resident's share and the depletion `depletion` names.
fn shares_view(vault: &Vault, depletion: Depletion<'_>) -> Result<ResidentSharesView> {
    let (reads, depleted) = match depletion {
        Depletion::NewestGeneration => (vault.resident_shares()?, true),
        Depletion::On(Some(allocation)) => (vault.resident_shares_on(allocation)?, true),
        Depletion::On(None) => (vault.resident_shares()?, false),
    };
    Ok(ResidentSharesView {
        residents: reads
            .into_iter()
            .map(|read| {
                let mut view = ResidentShareView {
                    resident: read.resident.to_hex(),
                    units: read.share.units,
                    pinned: read.share.pinned,
                    allocation: None,
                    allocation_generation: None,
                    used_units: 0,
                    overdraft_units: 0,
                    overdrafts: 0,
                };
                if depleted {
                    view.allocation_generation = read.allocation.as_ref().map(|at| at.generation);
                    view.allocation = read.allocation.map(|at| at.id);
                    view.used_units = read.used_units;
                    view.overdraft_units = read.overdraft_units;
                    view.overdrafts = read.overdrafts;
                }
                view
            })
            .collect(),
    })
}

/// Reads every resident's share and depletion, each on its newest charged
/// generation. The embedded verb row calls this: an embedded vault has no
/// host account to name the allocation.
pub fn resident_shares_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    shares_view(vault, Depletion::NewestGeneration)
}

/// Reads every resident's share and depletion on `allocation`, the host
/// account's `AccountStatus::resident_share_allocation`, which the server
/// door passes. With `None` (no walletless allocation) it shows the settings
/// with no depletion.
pub fn resident_shares_on_allocation_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
    allocation: Option<&AllocationRef>,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    shares_view(vault, Depletion::On(allocation))
}

/// Sets one resident's share as the owner asks; its depletion stays as it
/// stands. Answers the view on each resident's newest charged generation
/// (the embedded verb row; see [`resident_shares_as_owner`]).
pub fn set_resident_share_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
) -> Result<ResidentSharesView> {
    set_resident_share(vault, owner, input)?;
    shares_view(vault, Depletion::NewestGeneration)
}

/// Sets one resident's share as the owner asks; its depletion stays as it
/// stands. Answers the view on `allocation`, as
/// [`resident_shares_on_allocation_as_owner`] does.
pub fn set_resident_share_on_allocation_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
    allocation: Option<&AllocationRef>,
) -> Result<ResidentSharesView> {
    set_resident_share(vault, owner, input)?;
    shares_view(vault, Depletion::On(allocation))
}

/// Checks the owner's proof and writes the resident's new share.
fn set_resident_share(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
) -> Result<()> {
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
    Ok(())
}
