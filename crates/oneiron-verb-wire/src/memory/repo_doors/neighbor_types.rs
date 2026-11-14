//! Moved from `crates/oneiron/src/memory/repo_doors/neighbor_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::codebase_doors::neighbor_types::CodeRelationDirection;
use crate::memory::codebase_doors::neighbor_types::CodeRelationKind;
use crate::memory::codebase_doors::neighbor_types::CodeSnapshotNeighbor;
use crate::memory::codebase_doors::neighbor_types::CodeSnapshotSymbolCitation;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The run's exact seed in a snapshot of the repo at its admitted full ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoSymbolsNeighborsInput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    pub symbol: EntityId,
    pub path: String,
    pub kinds: Option<Vec<CodeRelationKind>>,
    pub direction: Option<CodeRelationDirection>,
}

/// One-hop recorded relations whose two endpoints this run can read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoSymbolsNeighborsOutput {
    pub repo: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub snapshot: String,
    pub seed: CodeSnapshotSymbolCitation,
    pub neighbors: Vec<CodeSnapshotNeighbor>,
}
