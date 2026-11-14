//! Moved from `crates/oneiron/src/query_expansion.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;

#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct GroundingContext {
    pub bindings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HydeRequest {
    pub query: String,
    pub max_subqueries: usize,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HydeExpansion {
    pub grounded_query: String,
    pub hypothetical_answer: String,
    pub embedding: Vec<f32>,
    pub subqueries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletionCandidate {
    pub id: EntityId,
    pub score: f32,
    pub claim: Option<oneiron_store::write_envelope::claim_body::ClaimBody>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompletionRequest {
    pub query: String,
    pub candidates: Vec<CompletionCandidate>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum EvidenceVerdict {
    Sufficient,
    Insufficient { gaps: Vec<String> },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct HydeOptions {
    pub channel_limit: usize,
    pub retry_once: bool,
}

impl HydeOptions {
    pub fn validate(&self) -> Result<()> {
        if self.channel_limit == 0 {
            return Err(Error::InvalidConfig(
                "hyde channel_limit must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}
pub mod host;
