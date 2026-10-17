//! The invitation rows of a shared vault (OF-531 / OF-158): `vault.members.add`
//! invites, and the invitee lists, accepts or declines their own invitation
//! under their own proof while an `add_member` holder may withdraw it. Each fn
//! passes the engine exactly what it asks for.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::federation::{SharedActExecutionReceipt, SharedInvitation};
use crate::memory::{MemoryError, MemoryResult};
use crate::task_verb::sdk::SharedVaultRequest;
use crate::{EntityId, Vault};

/// One of the caller's own invitations, by the id its `MemberInvited`
/// receipt named.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationRequest {
    pub vault_id: u64,
    pub invitation: String,
}

/// `vault.members.withdraw_invitation`'s input: the invitee's PERSON id, hex,
/// and the invitation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationWithdrawRequest {
    pub vault_id: u64,
    pub member: String,
    pub invitation: String,
}

/// `vault.members.invitations`: the caller's own pending invitations.
pub fn read_shared_invitations(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    input: SharedVaultRequest,
) -> MemoryResult<Vec<SharedInvitation>> {
    Ok(vault.shared_invitations(reader, input.vault_id)?)
}

/// `vault.members.accept`: the invitee joins at the invited role.
pub fn accept_shared_invitation_as(
    vault: &Vault,
    invitee: &AuthenticatedOwner,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.accept_shared_invitation(invitee, input.vault_id, &input.invitation)?)
}

/// `vault.members.decline`: the invitee declines; nothing is granted.
pub fn decline_shared_invitation_as(
    vault: &Vault,
    invitee: &AuthenticatedOwner,
    input: SharedInvitationRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    Ok(vault.decline_shared_invitation(invitee, input.vault_id, &input.invitation)?)
}

/// `vault.members.withdraw_invitation`: an `add_member` holder takes a
/// pending invitation back.
pub fn withdraw_shared_invitation_as(
    vault: &Vault,
    admin: &AuthenticatedOwner,
    input: SharedInvitationWithdrawRequest,
) -> MemoryResult<SharedActExecutionReceipt> {
    let member = EntityId::from_hex(&input.member)
        .map_err(|_| MemoryError::bad_request("member is not an entity id"))?;
    Ok(vault.withdraw_shared_invitation(admin, input.vault_id, member, &input.invitation)?)
}
