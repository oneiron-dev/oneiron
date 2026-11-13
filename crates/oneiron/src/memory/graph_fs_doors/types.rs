//! Graph filesystem request, plan, entry and output records.
//! `GraphFsMountRequest` is the first of its records.
//! These are local definitions; `memory::graph_fs_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadReceipt;
use crate::graph_fs::GraphFsReference;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::graph_fs_doors::types::{
    GraphFsDirectoryView, GraphFsEncoding, GraphFsEntryView, GraphFsFindRequest,
    GraphFsGrepRequest, GraphFsHeadRequest, GraphFsKind, GraphFsLinkRequest, GraphFsLinkView,
    GraphFsLsRequest, GraphFsMountRequest, GraphFsMounted, GraphFsOutput, GraphFsPathRequest,
    GraphFsPlan,
};
