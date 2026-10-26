//! `vault.connectors.read_grants.revoke` (FIX 10895): the owner revokes an
//! agent's witness-read grant over a connector conversation, the grant the
//! engine issued when the agent first witnessed the conversation and the
//! one the consent registry lists with this verb as its one-tap revoke. A
//! revoked grant stays revoked: no later witness issues it again.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;

/// `vault.connectors.read_grants.revoke`'s input: the grant, by its id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWitnessReadGrantRevokeRequest {
    /// The grant's ACCESS_GRANT row (32 hex), as its consent registry row
    /// names it.
    pub grant_ref: EntityId,
}

/// `vault.connectors.read_grants.revoke`'s answer: the grant as it now
/// stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWitnessReadGrantRevoked {
    pub grant_ref: EntityId,
    /// False when the grant was already revoked and this call changed
    /// nothing.
    pub changed: bool,
    /// The agent the grant let read.
    pub agent: EntityId,
    /// The connector conversation whose MESSAGEs it let the agent read.
    pub conversation: EntityId,
    /// Why the engine issued it: `connector_witness_read`.
    pub reason: String,
    /// When it was revoked (Unix seconds).
    pub revoked_at: u64,
}

/// `vault.connectors.read_grants.revoke` under the owner's proof. A repeat
/// answers `changed: false`; an id that names no witness-read grant is not
/// found.
pub fn revoke_connector_witness_read_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ConnectorWitnessReadGrantRevokeRequest,
) -> MemoryResult<ConnectorWitnessReadGrantRevoked> {
    let revoke = vault.revoke_connector_witness_read_grant(
        owner,
        &input.grant_ref,
        crate::unix_seconds_now(),
    )?;
    Ok(ConnectorWitnessReadGrantRevoked {
        grant_ref: input.grant_ref,
        changed: revoke.changed,
        agent: revoke.grant.principal_ref,
        conversation: revoke.conversation,
        reason: crate::ingest::CONNECTOR_WITNESS_READ_REASON.to_owned(),
        revoked_at: revoke.grant.revoked_at.unwrap_or_default(),
    })
}
