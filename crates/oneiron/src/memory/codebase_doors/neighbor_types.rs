//! Typed one-hop code relations within a single pinned snapshot.

use serde::{Deserialize, Serialize};

use super::CodeSnapshotDefinition;
use crate::EntityId;
use crate::edge::EdgeKind;

/// The relation kinds recorded by the snapshot's extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeRelationKind {
    Calls,
    Imports,
    Refs,
}

impl CodeRelationKind {
    pub(crate) fn edge_kind(self) -> EdgeKind {
        match self {
            Self::Calls => EdgeKind::Calls,
            Self::Imports => EdgeKind::Imports,
            Self::Refs => EdgeKind::Refs,
        }
    }

    pub(crate) fn from_edge(kind: EdgeKind) -> Option<Self> {
        match kind {
            EdgeKind::Calls => Some(Self::Calls),
            EdgeKind::Imports => Some(Self::Imports),
            EdgeKind::Refs => Some(Self::Refs),
            _ => None,
        }
    }
}

/// Which direction of the recorded relation to read from the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeRelationDirection {
    In,
    Out,
    Both,
}

pub(crate) const DEFAULT_CODE_RELATION_DIRECTION: CodeRelationDirection =
    CodeRelationDirection::Both;
pub(crate) const DEFAULT_CODE_RELATION_KINDS: [CodeRelationKind; 3] = [
    CodeRelationKind::Calls,
    CodeRelationKind::Imports,
    CodeRelationKind::Refs,
];

/// One-hop neighbors of an exact symbol in this artifact's pinned manifest.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeSnapshotNeighborsRequest {
    pub repo: EntityId,
    pub snapshot: String,
    /// An id returned by the pinned snapshot's definitions door. Not authority.
    pub symbol: EntityId,
    /// The seed's exact manifest path, admitted before a run resolves the snapshot.
    pub path: String,
    /// Absent selects all recorded relation kinds. An empty list selects none.
    pub kinds: Option<Vec<CodeRelationKind>>,
    /// Absent reads both incoming and outgoing relations.
    pub direction: Option<CodeRelationDirection>,
}

/// A symbol revision and the full-file hash from the same pinned snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotSymbolCitation {
    pub definition: CodeSnapshotDefinition,
    /// Full-file BLAKE3, not a symbol-text SHA-256 or a document version.
    pub content_hash_blake3: String,
}

/// One recorded edge between two readable revisions, preserving its direction.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotNeighbor {
    pub kind: CodeRelationKind,
    pub source: CodeSnapshotSymbolCitation,
    pub target: CodeSnapshotSymbolCitation,
}

/// One-hop facts from this snapshot only, in stored relation order. No PPR scores.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeSnapshotNeighborsView {
    pub repo: EntityId,
    pub snapshot: String,
    pub seed: CodeSnapshotSymbolCitation,
    pub neighbors: Vec<CodeSnapshotNeighbor>,
}
