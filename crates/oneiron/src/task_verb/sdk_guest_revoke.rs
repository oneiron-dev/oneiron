//! The input and answer of the owner's guest revoke row (OF-232):
//! `vault.guests.revoke`, a host door. A server withdraws the guest's grant
//! under the vault owner's proof, as `/v1/owner/guests/revoke` takes it, and
//! hands the engine its own slip issuer, which signs each pact disconnect.
//! An embedded handle holds no host signing key, so it refuses after the
//! owner check. With `peer`, the former peer's host origin, the server also
//! queues one courtesy-delete ask per ended pact once the revoke is durable
//! (FIX 1634); this crate holds no outbox door, so the engine call here
//! never reads it.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::receipt::{GuestRevokeResponse, project_guest_revoke};

/// `vault.guests.revoke`'s input: the guest's FEDERATION_GRANT, an ask
/// guest's or a Connect peer's, and where to send the courtesy deletes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeRequest {
    pub grant_ref: EntityId,
    /// The former peer's host origin, `https://host[:port]`, as
    /// `vault.courtesy_delete.send` takes it: the server queues one
    /// courtesy-delete ask to it per courtesy target. No grant or pact
    /// records it; omitted, the revoke sends nothing.
    #[serde(
        default = "default_guest_revoke_peer",
        skip_serializing_if = "Option::is_none"
    )]
    pub peer: Option<String>,
}

/// The courtesy deletes a revoke sends with no origin named: none. No grant
/// or pact records the peer's host, and a revoke never guesses one.
const DEFAULT_GUEST_REVOKE_PEER: Option<String> = None;

fn default_guest_revoke_peer() -> Option<String> {
    DEFAULT_GUEST_REVOKE_PEER
}

/// `vault.guests.revoke` on a server: [`Vault::revoke_guest_access`] under
/// the owner's proof and the host's own `issuer`, projected through
/// [`project_guest_revoke`]. A repeat answers the first revoke with
/// `changed: false`; an unknown or non-guest grant is not found. `peer` is
/// the server's to send to, after this returns.
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
