//! Typed inputs and outputs of the run's pinned relation-neighbor read.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::codebase_doors::{
    CodeRelationDirection, CodeRelationKind, CodeSnapshotNeighbor, CodeSnapshotSymbolCitation,
};

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
