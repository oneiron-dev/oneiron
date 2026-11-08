//! Core half of `store::code_revision_record`: its store-layer items live in `oneiron_store::code_revision_record` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::code_revision_record::*;

use crate::entity_id::EntityId;
pub use crate::store::code_commit_metadata::CodeCommitMetadata;
use crate::store::code_document_values::CodeDocumentFrontier;
pub use crate::store::code_tree_blob::CodeTreeBlob;
use serde::{Deserialize, Serialize};
pub use tree_inventory::CodeTreeInventory;
pub use types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};

pub mod codec;
pub(crate) mod commit_metadata;
pub(crate) mod file_frontiers;
pub(crate) mod tables;
pub(crate) mod tree_codec;
pub(crate) mod tree_inventory;
mod types;
