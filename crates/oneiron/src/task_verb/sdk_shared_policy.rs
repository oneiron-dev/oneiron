//! The shared-act policy rows a host door answers (DOOR-129):
//! `vault.shared.policy.get` reads every row a live Owner may inspect,
//! `.propose` proposes one row change, `.answer` approves or vetoes it under
//! the answerer's own credential and `.change` reads one change back. Each fn
//! passes the engine exactly what it asks for; no input names another
//! Owner, a time or an approval count.
use serde::{Deserialize, Serialize};

use super::sdk_shared::SharedVaultRequest;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::federation::{SharedActPoliciesView, SharedActPolicy, SharedActPolicyChange};
use crate::memory::MemoryResult;

/// `vault.shared.policy.propose`'s input: the act's new row, against the
/// `policy_hash` the proposer read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyProposeRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    /// The act the row names, as `vault.shared.policy.get` lists it.
    pub act: String,
    /// The act's whole new row, or `null` to remove the vault's own row so
    /// the shipped row applies again. Required: an omitted row is refused.
    #[serde(deserialize_with = "Option::deserialize")]
    pub policy: Option<SharedActPolicy>,
    /// The `policy_hash` of the rows the proposer read.
    pub expected_policy_hash: String,
}

/// A shared-act policy change, by the id its proposal answered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyChangeRequest {
    pub change_id: String,
}

/// `vault.shared.policy.answer`'s input: the caller's yes or no.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedActPolicyAnswerRequest {
    pub change_id: String,
    pub approve: bool,
}

/// `vault.shared.policy.get`: every shared-act policy row of the vault.
pub fn read_shared_act_policies(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<SharedActPoliciesView> {
    Ok(vault.shared_act_policies(owner, input.vault_id)?)
}

/// `vault.shared.policy.propose`: propose one row change.
pub fn propose_shared_act_policy_change(
    vault: &Vault,
    proposer: &AuthenticatedOwner,
    input: SharedActPolicyProposeRequest,
) -> MemoryResult<SharedActPolicyChange> {
    Ok(vault.propose_shared_act_policy_change(
        proposer,
        input.vault_id,
        &input.act,
        input.policy,
        &input.expected_policy_hash,
    )?)
}

/// `vault.shared.policy.answer`: approve or veto one change.
pub fn answer_shared_act_policy_change(
    vault: &Vault,
    holder: &AuthenticatedOwner,
    input: SharedActPolicyAnswerRequest,
) -> MemoryResult<SharedActPolicyChange> {
    Ok(vault.answer_shared_act_policy_change(holder, &input.change_id, input.approve)?)
}

/// `vault.shared.policy.change`: one change and its answers.
pub fn read_shared_act_policy_change(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SharedActPolicyChangeRequest,
) -> MemoryResult<SharedActPolicyChange> {
    Ok(vault.shared_act_policy_change(owner, &input.change_id)?)
}
