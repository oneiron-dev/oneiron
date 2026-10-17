//! The input and answer of the owner's guest revoke row (OF-232):
//! `vault.guests.revoke`, a host door. A server withdraws the guest's grant
//! under the vault owner's proof, as `/v1/owner/guests/revoke` takes it, and
//! hands the engine its own slip issuer, which signs each pact disconnect.
//! An embedded handle holds no host signing key, so it refuses after the
//! owner check.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::receipt::{GuestRevokeResponse, project_guest_revoke};

/// `vault.guests.revoke`'s input: the ask guest's FEDERATION_GRANT.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeRequest {
    pub grant_ref: EntityId,
}

/// `vault.guests.revoke` on a server: [`Vault::revoke_guest_access`] under
/// the owner's proof and the host's own `issuer`, projected through
/// [`project_guest_revoke`]. A repeat answers the first revoke with
/// `changed: false`; an unknown or non-guest grant is not found.
pub fn revoke_guest_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: GuestRevokeRequest,
) -> MemoryResult<GuestRevokeResponse> {
    let outcome = vault.revoke_guest_access(owner, issuer, input.grant_ref)?;
    Ok(project_guest_revoke(outcome))
}

/// `vault.guests.revoke` on an embedded handle: the owner's call, refused,
/// because the disconnects are signed with a host key no embedded vault
/// holds.
pub fn revoke_guest_embedded(
    memory: &Memory<'_>,
    _input: GuestRevokeRequest,
) -> MemoryResult<GuestRevokeResponse> {
    let _owner = memory.embedded_owner("vault.guests.revoke")?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "vault.guests.revoke signs each pact disconnect with the host's own key; an embedded vault holds none",
        &["Call it through a remote client of the server that hosts the guest."],
    ))
}
