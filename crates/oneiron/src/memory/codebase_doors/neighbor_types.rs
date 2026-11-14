//! Typed one-hop code relations within a single pinned snapshot.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::codebase_doors::neighbor_types::{
    CodeRelationDirection, CodeRelationKind, CodeSnapshotNeighbor, CodeSnapshotNeighborsRequest,
    CodeSnapshotNeighborsView, CodeSnapshotSymbolCitation,
};

pub(crate) const DEFAULT_CODE_RELATION_DIRECTION: CodeRelationDirection =
    CodeRelationDirection::Both;
pub(crate) const DEFAULT_CODE_RELATION_KINDS: [CodeRelationKind; 3] = [
    CodeRelationKind::Calls,
    CodeRelationKind::Imports,
    CodeRelationKind::Refs,
];
