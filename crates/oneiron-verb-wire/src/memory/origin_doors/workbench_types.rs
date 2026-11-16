//! Moved from `crates/oneiron/src/memory/origin_doors/workbench_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One served code repository to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRepoGetRequest {
    /// The served repository's CODE_ARTIFACT anchor.
    pub repo: EntityId,
}

/// One durable revision fork of a served repository to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeForkGetRequest {
    pub repo: EntityId,
    pub fork_session: EntityId,
}

/// One received ref of one push to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodePushIngressGetRequest {
    pub repo: EntityId,
    /// The push's receive-pack provenance claim.
    pub provenance: EntityId,
    /// The full ref name.
    pub ref_name: String,
}
