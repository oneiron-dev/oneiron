//! Stored retrieval policy actions, trajectories and learned evidence.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyIdentity {
    pub user: EntityId,
    pub persona: Option<EntityId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyTier {
    User,
    Persona,
    /// Only this account's evidence. No cross-vault or cross-account lookup.
    Global,
    Seed,
}

pub mod posterior;
