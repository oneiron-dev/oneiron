//! Graph filesystem request, plan, entry and output records.
//! `GraphFsMountRequest` is the first of its records.
//! These are local definitions; `memory::graph_fs_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadReceipt;
use crate::graph_fs::GraphFsReference;

/// The file face's content selector and page bounds. Neither grants access.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsMountRequest {
    #[serde(rename = "ref")]
    pub reference: GraphFsReference,
    #[serde(default)]
    pub page_byte_cap: Option<usize>,
    #[serde(default)]
    pub max_entries: Option<usize>,
}

/// A reusable, stateless mount descriptor. Every operation rechecks the
/// caller's credential. Snapshot ids are resolved to their exact fork hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphFsMounted {
    pub mount: GraphFsMountRequest,
    pub root: String,
    pub projection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsPathRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsLinkRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsLsRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub by_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsFindRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub newer_than: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsGrepRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
    pub pattern: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphFsHeadRequest {
    pub mount: GraphFsMountRequest,
    pub path: String,
    #[serde(default)]
    pub lines: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::memory::graph_fs_doors::types::{
    GraphFsEncoding, GraphFsEntryView, GraphFsKind, GraphFsPlan,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphFsDirectoryView {
    pub mount: GraphFsMountRequest,
    pub path: String,
    pub entries: Vec<GraphFsEntryView>,
    pub next_cursor: Option<String>,
    /// The scoped point-read receipt already attached to this page.
    pub read_receipt: Option<ScopedReadReceipt>,
}

/// Joining pages after decoding each by its encoding yields the file bytes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphFsOutput {
    pub mount: GraphFsMountRequest,
    pub path: String,
    pub output: String,
    pub encoding: GraphFsEncoding,
    pub next_cursor: Option<String>,
    pub plan: GraphFsPlan,
    /// The command's existing folded scoped-read receipt.
    pub read_receipt: Option<ScopedReadReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraphFsLinkView {
    pub mount: GraphFsMountRequest,
    pub path: String,
    pub target: Option<String>,
    /// The actual scoped point-read receipt; absent when no read ran.
    pub read_receipt: Option<ScopedReadReceipt>,
}
