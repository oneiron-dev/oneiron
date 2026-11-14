//! Moved from `crates/oneiron/src/verbs/connector_witness_read_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
}
