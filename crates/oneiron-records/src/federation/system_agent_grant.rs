//! Moved from `crates/oneiron/src/federation/system_agent_grant.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::federation::system_agent_grant::narrowing::SystemAgentNarrowing;
pub use crate::federation::system_agent_grant::narrowing::SystemFunction;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Why the engine stood a grant on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineDefaultOrigin {
    /// The engine's default at vault creation: a base agent's Steward grant,
    /// stood when a host first opened the vault.
    EngineDefaultAtVaultCreation,
}

/// The receipt of a grant the engine stood by default (lead 10 Nov 06:5x):
/// the engine's act, which no owner signed. The owner reads it on first
/// open and narrows or revokes the grant as any Steward grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineDefaultGrant {
    /// The agent the grant names.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub agent: EntityId,
    /// The verbs it held when the engine stood it.
    pub verbs: BTreeSet<String>,
    pub origin: EngineDefaultOrigin,
    pub created_at: u64,
}
pub mod narrowing;
