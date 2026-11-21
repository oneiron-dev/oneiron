//! Doors for ending a member's standing between the door's check and write.

use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::federation::SharedActExecutionReceipt;
use crate::{EntityId, Vault};

/// [`Vault::remove_shared_member`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::remove_shared_member`].
pub fn remove_shared_member_between(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    vault_id: u64,
    member: EntityId,
    slips: Option<&HostSlipIssuer>,
    between: impl FnOnce(),
) -> Result<SharedActExecutionReceipt> {
    vault.remove_shared_member_for_ask_between(admin, vault_id, member, slips, None, None, between)
}

/// [`Vault::leave_shared_vault`] with `between` run after the door asked and before its
/// write opens.
///
/// # Errors
/// As [`Vault::leave_shared_vault`].
pub fn leave_shared_vault_between(
    vault: &Vault,
    member: &AuthenticatedOwner,
    vault_id: u64,
    slips: Option<&HostSlipIssuer>,
    between: impl FnOnce(),
) -> Result<SharedActExecutionReceipt> {
    vault.leave_shared_vault_between(member, vault_id, slips, between)
}
