//! Typed inputs and outputs of the run's pinned relation-neighbor read.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::codebase_doors::{
    CodeRelationDirection, CodeRelationKind, CodeSnapshotNeighbor, CodeSnapshotSymbolCitation,
};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::repo_doors::neighbor_types::{
    RepoSymbolsNeighborsInput, RepoSymbolsNeighborsOutput,
};
