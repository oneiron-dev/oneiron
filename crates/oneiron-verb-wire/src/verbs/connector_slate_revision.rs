//! Moved from `crates/oneiron/src/verbs/connector_slate_revision.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::slate_revision::ConnectorRevisionDeferral;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

pub fn id(value: &str, field: &'static str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value).map_err(|_| MemoryError::bad_request(field))
}

/// `vault.connectors.slates.revision_offers`: the revisions waiting on the
/// owner, optionally for one catalog connector.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRevisionOffersRequest {
    #[serde(default)]
    pub connector: Option<String>,
}

/// `vault.connectors.slates.defer_revision`: the owner holds a scope
/// revision's offer back, or lets it surface again.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSlateRevisionDeferRequest {
    /// The scope signal whose offer it is, 32 hex.
    pub signal_ref: String,
    pub deferral: ConnectorRevisionDeferral,
}

/// One grant an accepted scope revision minted, with its per-grant key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorRevisionGrantView {
    pub tool: String,
    pub grant_id: String,
    pub key_id: String,
    pub key_connector: String,
}

/// One key, or one row of it, that depends on a credential slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBindingDependentView {
    /// The catalog key or a per-grant key derived from it, 32 hex.
    pub key_ref: String,
    /// The row (a tool, or `@elicitation`); absent: every row the key calls.
    #[serde(default)]
    pub tool: Option<String>,
}

/// `vault.connectors.slates.reask_issuer`: the owner's observation of the
/// issuer one catalog connector's credential slot answers for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIssuerReaskRequest {
    /// The catalog connector's name.
    pub connector: String,
    /// The credential slot: `route`, or a custody record's name.
    pub slot: String,
    /// The issuer the slot's credential answers for now.
    pub issuer: String,
    /// The custody pointer or fingerprint presented now, never a value.
    pub credential_ref: String,
    /// The binding generation he read: 0 for the first observation.
    pub expected_generation: u64,
    /// The keys and rows that depend on the slot; empty keeps the binding's.
    #[serde(default)]
    pub dependents: Vec<ConnectorBindingDependentView>,
    /// What was observed, in words: never a credential.
    pub witness: String,
}
