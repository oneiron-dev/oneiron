//! Owner setup of sealed cohorts through the eval-authoring mechanism.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill_optimize::{
    EvalAuthoringInventory, EvalAuthoringReport, EvalCohortSetup, eval_authoring_inventory,
    setup_eval_cohorts,
};
use crate::Vault;

/// Pin the returned `built_at` and `inventory_digest` when setting up cohorts.
/// An omitted time reads the vault clock; a future inventory is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalInventoryWire {
    #[serde(default)]
    pub at: Option<u64>,
}

pub fn eval_inventory_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalInventoryWire,
) -> MemoryResult<EvalAuthoringInventory> {
    owner.revalidate_person(vault)?;
    let now = vault.now_recorded_at();
    let at = input.at.unwrap_or(now);
    if at > now {
        return Err(MemoryError::bad_request("an eval inventory cannot be in the future"));
    }
    Ok(eval_authoring_inventory(vault, at)?)
}

pub fn eval_cohorts_setup_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: EvalCohortSetup,
) -> MemoryResult<EvalAuthoringReport> {
    Ok(setup_eval_cohorts(vault, owner, input, vault.now_recorded_at())?)
}
