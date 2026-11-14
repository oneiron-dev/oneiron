//! Moved from `crates/oneiron/src/memory/graph_fs_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraphFsEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraphFsPlan {
    Pushdown,
    Walk,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraphFsKind {
    Directory,
    File,
    Symlink,
    Cursor,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphFsEntryView {
    pub name: String,
    pub kind: GraphFsKind,
    pub target: Option<String>,
    pub cursor: Option<String>,
    pub byte_len: Option<usize>,
}
