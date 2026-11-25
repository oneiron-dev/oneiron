//! Typed owner doors over the resident shares (FIX 11310): set one
//! resident's share of the host-paid allocation in one walletless unit, and
//! read every resident's share and depletion, one block per walletless unit
//! (Engine RESIDENT-SHARE-UNIT = A). The vault's resident ledger owns every
//! admission rule; these doors only check the owner's proof and project.

use super::{AccountStatus, LeaseUnit, ResidentShare};
use crate::consent::AuthenticatedOwner;
use crate::llm::ResidentShareRead;
use crate::{EntityId, Error, Result, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::run_admission::resident_doors::{
    ResidentShareView, ResidentSharesRequest, ResidentSharesView, SetResidentShareRequest,
    UnitSharesView,
};

/// One unit's block: each resident's share in `unit`, and the depletion in
/// `reads` beside it when `depleted`.
fn block(unit: &LeaseUnit, reads: Vec<ResidentShareRead>, depleted: bool) -> UnitSharesView {
    UnitSharesView {
        unit: unit.as_str().to_owned(),
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
    }
}

/// One block per unit a share is set in, each resident's depletion on its
/// newest charged generation in that unit when `depleted`.
fn blocks_by_unit(vault: &Vault, depleted: bool) -> Result<ResidentSharesView> {
    let allocations = vault
        .resident_share_units()?
        .iter()
        .map(|unit| Ok(block(unit, vault.resident_shares(unit)?, depleted)))
        .collect::<Result<_>>()?;
    Ok(ResidentSharesView { allocations })
}

/// One block per walletless allocation `account` selects, each with the
/// shares in its unit and the depletion on that allocation (row M2-I). With
/// none selected, the shares govern nothing: one block per unit a share is
/// set in, with no depletion, never another wallet's usage (review 10403
/// P1-2).
fn blocks_on_account(vault: &Vault, account: &AccountStatus) -> Result<ResidentSharesView> {
    let walletless: Vec<_> = account.walletless_allocations().collect();
    if walletless.is_empty() {
        return blocks_by_unit(vault, false);
    }
    let allocations = walletless
        .into_iter()
        .map(|selected| {
            let reads = vault.resident_shares_on(&selected.unit, &selected.reference)?;
            Ok(block(&selected.unit, reads, true))
        })
        .collect::<Result<_>>()?;
    Ok(ResidentSharesView { allocations })
}

/// Reads every resident's share and depletion, one block per unit a share
/// is set in, each on its newest charged generation in that unit. The
/// embedded verb row calls this: an embedded vault has no host account to
/// name the allocation.
pub fn resident_shares_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    blocks_by_unit(vault, true)
}

/// Reads every resident's share and depletion, one block per walletless
/// allocation the host `account` selects. The server door passes its host
/// account's status.
pub fn resident_shares_on_account_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &ResidentSharesRequest,
    account: &AccountStatus,
) -> Result<ResidentSharesView> {
    owner.revalidate(vault)?;
    blocks_on_account(vault, account)
}

/// Sets one resident's share in the unit the request names as the owner
/// asks; its depletion stays as it stands. An embedded vault has no host
/// account, so the request must name its unit. Answers the view
/// [`resident_shares_as_owner`] reads.
pub fn set_resident_share_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
) -> Result<ResidentSharesView> {
    set_resident_share(vault, owner, input, &[])?;
    blocks_by_unit(vault, true)
}

/// Sets one resident's share as the owner asks, in the unit the request
/// names, else in the one walletless unit `account` selects; its depletion
/// stays as it stands. Answers the view
/// [`resident_shares_on_account_as_owner`] reads.
pub fn set_resident_share_on_account_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
    account: &AccountStatus,
) -> Result<ResidentSharesView> {
    let walletless: Vec<LeaseUnit> = account
        .walletless_allocations()
        .map(|selected| selected.unit.clone())
        .collect();
    set_resident_share(vault, owner, input, &walletless)?;
    blocks_on_account(vault, account)
}

/// Checks the owner's proof and writes the resident's new share in the
/// request's unit. A request that names no unit takes the one unit in
/// `walletless`; with none or several it is refused with `unit_required`
/// (Engine RESIDENT-SHARE-UNIT = A).
fn set_resident_share(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SetResidentShareRequest,
    walletless: &[LeaseUnit],
) -> Result<()> {
    owner.revalidate(vault)?;
    let resident = EntityId::from_hex(&input.resident)
        .map_err(|_| Error::InvalidConfig("resident is not an entity id".to_owned()))?;
    let unit = match (&input.unit, walletless) {
        (Some(unit), _) => LeaseUnit::new(unit.as_str())
            .map_err(|_| Error::InvalidConfig("unit is not a lease unit".to_owned()))?,
        (None, [only]) => only.clone(),
        (None, _) => {
            return Err(Error::InvalidConfig(format!(
                "unit_required: the host selects {} walletless units; name the share's unit",
                walletless.len()
            )));
        }
    };
    vault.set_resident_share(
        resident,
        &unit,
        ResidentShare {
            units: input.units,
            pinned: input.pinned,
        },
    )?;
    Ok(())
}
