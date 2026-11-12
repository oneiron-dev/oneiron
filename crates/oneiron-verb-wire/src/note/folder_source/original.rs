//! Moved from `crates/oneiron/src/note/folder_source/original.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A kept original: the version of its file's blob artifact that holds the
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileOriginal {
    /// The file's blob artifact, one per file across its versions.
    pub artifact: EntityId,
    /// The version that holds these bytes.
    pub version: u64,
    /// The bytes' blake3 hash, lower hex.
    pub content_hash: String,
}
