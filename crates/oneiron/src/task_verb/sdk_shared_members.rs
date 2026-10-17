//! The invitation rows of a shared vault (OF-531 / OF-158): `vault.members.add`
//! invites, and the invitee lists, accepts or declines their own invitation
//! under their own proof while an `add_member` holder may withdraw it. Beside
//! them, the owner's guest slip mint (OF-232). Each fn passes the engine
//! exactly what it asks for.
use serde::{Deserialize, Serialize};

use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::federation::{SharedActExecutionReceipt, SharedInvitation};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
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

/// `vault.guests.mint_slip`'s input: the ask guest's FEDERATION_GRANT, the
/// public key (64 hex) the guest generated on their own device, and when the
/// slip ends (Unix seconds).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestSlipMintRequest {
    pub grant_ref: EntityId,
    pub holder_key: String,
    pub expires_at: u64,
}

/// `vault.guests.mint_slip`'s answer: the slip credential for the guest, who
/// proves each request with their own key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestSlipMinted {
    /// The slip id, hex.
    pub slip_id: String,
    /// The `v2.slip.` credential.
    pub slip: String,
    pub expires_at: u64,
}

fn holder_key(hex: &str) -> MemoryResult<[u8; 32]> {
    let refused = || MemoryError::bad_request("holder_key is not 32 bytes of hex");
    if hex.len() != 64 {
        return Err(refused());
    }
    let mut key = [0; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(key)
}

/// `vault.guests.mint_slip` on a server: [`Vault::mint_guest_slip`] under the
/// owner's proof and the host's own `issuer`.
pub fn mint_guest_slip_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: GuestSlipMintRequest,
) -> MemoryResult<GuestSlipMinted> {
    let key = holder_key(&input.holder_key)?;
    let slip = vault.mint_guest_slip(owner, issuer, input.grant_ref, key, input.expires_at)?;
    Ok(GuestSlipMinted {
        slip_id: crate::entity_id::bytes_to_hex_lower(&slip.claims.slip_id),
        slip: slip.to_token()?,
        expires_at: slip.claims.expires_at,
    })
}

/// `vault.guests.mint_slip` on an embedded handle: the owner's call, refused,
/// because the slip is signed with a host key no embedded vault holds.
pub fn mint_guest_slip_embedded(
    memory: &Memory<'_>,
    _input: GuestSlipMintRequest,
) -> MemoryResult<GuestSlipMinted> {
    let _owner = memory.embedded_owner("vault.guests.mint_slip")?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "vault.guests.mint_slip signs the guest's slip with the host's own key; an embedded vault holds none",
        &["Call it through a remote client of the server that hosts the guest."],
    ))
}
