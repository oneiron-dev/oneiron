//! Doors for `tests/org_two_admin_rule.rs` (UNBUILT-06 PR 2, Sol review of
//! #8482, the approve cut short): `vault.members.held.approve` stopped by a
//! crash after its claim, before or after its re-run, and never settled.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::federation::HeldAdminAct;
use crate::memory::{MemoryError, MemoryResult};
use crate::verbs::{HeldAdminActRequest, SharedMemberAddRequest};

/// The approve of held act `input` by `approver`, cut short after its claim:
/// the act stands claimed by them, and its verb never ran.
pub fn claim_held_admin_act(
    vault: &Vault,
    approver: &AuthenticatedOwner,
    input: &HeldAdminActRequest,
) -> MemoryResult<HeldAdminAct> {
    Ok(vault
        .claim_held_admin_act(approver, input.vault_id, &input.held)?
        .0)
}

/// The approve of held `vault.members.add` act `input` by `approver`, cut
/// short after its re-run ran and before the approve door settled the act.
/// Answers the re-run's own answer.
pub fn approve_held_add_unsettled(
    vault: &Vault,
    approver: &AuthenticatedOwner,
    input: &HeldAdminActRequest,
) -> MemoryResult<serde_json::Value> {
    let (act, approval) = vault.claim_held_admin_act(approver, input.vault_id, &input.held)?;
    if act.verb != "vault.members.add" {
        return Err(MemoryError::bad_request("not a held vault.members.add act"));
    }
    let request: SharedMemberAddRequest = serde_json::from_value(act.input)
        .map_err(|_| MemoryError::bad_request("the held act's input no longer decodes"))?;
    let receipt = crate::federation::run_approved_admin_act(approval, || {
        crate::verbs::add_shared_member_as(vault, approver, request)
    })?;
    serde_json::to_value(receipt)
        .map_err(|_| MemoryError::bad_request("the held act's answer does not encode"))
}
