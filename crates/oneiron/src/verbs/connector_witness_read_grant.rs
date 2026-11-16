//! `vault.connectors.read_grants.revoke` (FIX 10895): the owner revokes an
//! agent's witness-read grant over a connector conversation, the grant the
//! engine issued when the agent first witnessed the conversation and the
//! one the consent registry lists with this verb as its one-tap revoke. A
//! revoked grant stays revoked: no later witness issues it again.
//! `vault.connectors.read_grants.grant` (FIX 10962) is the owner's grant
//! once more: it issues the grant anew at its same id.

use crate::Vault;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::connector_witness_read_grant::{
    ConnectorWitnessReadGrantRequest, ConnectorWitnessReadGrantRevokeRequest,
    ConnectorWitnessReadGrantRevoked, ConnectorWitnessReadGranted,
};

/// `vault.connectors.read_grants.revoke` under the owner's proof. A repeat
/// answers `changed: false`; an id that names no witness-read grant is not
/// found.
pub fn revoke_connector_witness_read_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: ConnectorWitnessReadGrantRevokeRequest,
) -> MemoryResult<ConnectorWitnessReadGrantRevoked> {
    let revoke = vault.revoke_connector_witness_read_grant(
        owner,
        surface,
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

/// `vault.connectors.read_grants.grant` under the owner's proof. A revoked
/// grant is issued anew; a repeat answers `changed: false`; an agent or a
/// connector conversation the vault does not hold is not found.
pub fn grant_connector_witness_read_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: ConnectorWitnessReadGrantRequest,
) -> MemoryResult<ConnectorWitnessReadGranted> {
    let granted = vault.grant_connector_witness_read_grant(
        owner,
        surface,
        input.agent,
        input.conversation,
        crate::unix_seconds_now(),
    )?;
    Ok(ConnectorWitnessReadGranted {
        grant_ref: granted.grant_ref,
        changed: granted.changed,
        agent: granted.grant.principal_ref,
        conversation: granted.conversation,
        reason: crate::ingest::CONNECTOR_WITNESS_READ_REASON.to_owned(),
        granted_at: granted.grant.created_at,
    })
}
