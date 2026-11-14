//! `vault.connectors.read_grants.revoke` (FIX 10895): the owner revokes an
//! agent's witness-read grant over a connector conversation, the grant the
//! engine issued when the agent first witnessed the conversation and the
//! one the consent registry lists with this verb as its one-tap revoke. A
//! revoked grant stays revoked: no later witness issues it again.
//! `vault.connectors.read_grants.grant` (FIX 10962) is the owner's grant
//! once more: it issues the grant anew at its same id.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::ActSurface;
use crate::check_in::{AppliedCheckIn, CheckInDecision};
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

/// `vault.connectors.read_grants.grant`'s input: the agent and the
/// connector conversation, which name the grant's one id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWitnessReadGrantRequest {
    /// The agent to read the conversation: its AGENT_DEF row (32 hex), as
    /// the consent registry row names it as `subject`.
    pub agent: EntityId,
    /// The connector conversation whose MESSAGEs the agent reads (32 hex).
    pub conversation: EntityId,
    /// Another asker's approved check-in for this exact grant, 32 hex: the
    /// owner applies it on their own proof, and the grant's writer spends it
    /// (ROLES-CHECKIN 2k8). Omitted: the owner's own grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

/// `vault.connectors.read_grants.grant`'s answer: the grant as it now
/// stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWitnessReadGranted {
    /// The grant's ACCESS_GRANT row (32 hex).
    pub grant_ref: EntityId,
    /// False when the grant was already active and this call changed
    /// nothing.
    pub changed: bool,
    /// The agent the grant lets read.
    pub agent: EntityId,
    /// The connector conversation whose MESSAGEs it lets the agent read.
    pub conversation: EntityId,
    /// Why the grant exists: `connector_witness_read`.
    pub reason: String,
    /// When the active grant was granted (Unix seconds).
    pub granted_at: u64,
    /// The decision a grant that changed ran on: the owner's own proof,
    /// naming the asker's approved check-in it applied (ROLES-CHECKIN 2k8).
    /// Absent when the call changed nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<CheckInDecision>,
}

/// `vault.connectors.read_grants.grant` under the owner's proof. A revoked
/// grant is issued anew; a repeat answers `changed: false`; an agent or a
/// connector conversation the vault does not hold is not found. The grant
/// widens the agent's reads: the owner's own grant goes on their own proof,
/// never gated, and the answer records that decision (`check_in`). With
/// `check_in_ref` the owner applies another asker's approved check-in for
/// this exact grant, spent in the grant's writer (ROLES-CHECKIN 2k8; Engine
/// RULING P25-SHAPE Q1 = A). A repeat that changes nothing spends nothing
/// and records none.
pub fn grant_connector_witness_read_grant_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: ConnectorWitnessReadGrantRequest,
) -> MemoryResult<ConnectorWitnessReadGranted> {
    let applied = match super::shared::check_in_ref(input.check_in_ref.as_deref())? {
        Some(id) => Some(AppliedCheckIn {
            id,
            verb: "vault.connectors.read_grants.grant",
            effect_digest: connector_witness_read_grant_effect_digest(&input)?,
        }),
        None => None,
    };
    let (granted, decision) = vault.grant_connector_witness_read_grant(
        owner,
        surface,
        input.agent,
        input.conversation,
        crate::unix_seconds_now(),
        applied.as_ref(),
    )?;
    Ok(ConnectorWitnessReadGranted {
        grant_ref: granted.grant_ref,
        changed: granted.changed,
        agent: granted.grant.principal_ref,
        conversation: granted.conversation,
        reason: crate::ingest::CONNECTOR_WITNESS_READ_REASON.to_owned(),
        granted_at: granted.grant.created_at,
        check_in: decision,
    })
}

/// The digest of the owner's witness-read grant `request`: the effect an
/// asker's `vault.check_in.open` names for
/// `vault.connectors.read_grants.grant`, and the one the owner's grant
/// spends (2k8; P25-SHAPE Q1 = A). BLAKE3, key derived from `oneiron
/// check_in connector witness read grant v1`, over the request's
/// MessagePack encoding with field names, without its `check_in_ref`: the
/// agent and the conversation.
///
/// # Errors
///
/// The request does not encode.
pub fn connector_witness_read_grant_effect_digest(
    request: &ConnectorWitnessReadGrantRequest,
) -> MemoryResult<[u8; 32]> {
    let grant = ConnectorWitnessReadGrantRequest {
        check_in_ref: None,
        ..request.clone()
    };
    let encoded = rmp_serde::to_vec_named(&grant).map_err(|_| {
        crate::error::Error::InvariantViolation("connector witness read grant encode")
    })?;
    let mut hasher =
        blake3::Hasher::new_derive_key("oneiron check_in connector witness read grant v1");
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}
