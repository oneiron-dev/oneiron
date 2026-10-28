//! Typed owner doors over the resident shares (FIX 11310): set one
//! resident's share of the host-paid allocation, and read every resident's
//! share and depletion. The vault's resident ledger owns every admission
//! rule; these doors only check the owner's proof and project.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use super::ResidentShare;
use crate::{EntityId, Error, Result, Vault};

/// Every resident share on record: no selector names another vault's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidentSharesRequest {}

/// The owner's setting for one resident's share.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetResidentShareRequest {
    /// The resident, as its entity id in hex.
    pub resident: String,
    /// The share in the allocation's unit; absent returns the resident to
    /// the default split of what the set shares leave.
    #[serde(default)]
    pub units: Option<u64>,
    /// Pinned, the share refuses the resident's new paid work once a call
    /// no longer fits it; soft, spend past it writes an overdraft receipt.
    #[serde(default)]
    pub pinned: bool,
}

/// One resident's share and its depletion on the allocation it last drew
/// on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidentShareView {
    pub resident: String,
    /// `None` is the default split.
    pub units: Option<u64>,
    pub pinned: bool,
    /// The allocation the counts are on, and its generation; `None` before
    /// any charge.
    pub allocation: Option<String>,
    pub allocation_generation: Option<u64>,
    pub used_units: u64,
    pub overdraft_units: u64,
    /// Settled calls that charged past the share.
    pub overdrafts: u64,
}

/// Every resident share on record, by resident.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidentSharesView {
    pub residents: Vec<ResidentShareView>,
}

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
