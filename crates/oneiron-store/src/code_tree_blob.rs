//! Untouched blob references and submodule mode in tested code trees.

use serde::{Deserialize, Serialize};

/// Git's mode of a submodule link. Kept visible, never exported.
pub const MODE_GITLINK: u32 = 0o160_000;

/// One untouched path of a tested tree: the Git object the checked tree
/// names, the BLAKE3 hash and size of its exact bytes, and its mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeTreeBlob {
    pub git_oid: String,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub mode: u32,
}
