//! Graph-FS read projection over the vault graph.
//!
//! This is a Plan-9-style read lens, not a storage backend: files are an
//! interface, while memory remains the typed bitemporal graph. Every directory
//! walk is a lazy query through [`crate::claim::ScopedRead`], bounded by a
//! cumulative byte cap and stable cursor order.

mod coreutils;
mod model;
mod paging;
mod readdir;

pub use self::model::{
    GRAPH_FS_COREUTILS_DEFAULT_RESULT_CAP, GRAPH_FS_COREUTILS_MAX_RESULT_CAP,
    GRAPH_FS_DEFAULT_MAX_ENTRIES, GRAPH_FS_DEFAULT_PAGE_BYTE_CAP, GRAPH_FS_HOST_IMPORTS,
    GRAPH_FS_MAX_PAGE_BYTE_CAP, GRAPH_FS_MAX_PAGE_ENTRIES, GRAPH_FS_MIN_PAGE_BYTE_CAP,
    GRAPH_FS_MORE_ENTRY, GRAPH_FS_PROJECTION_VERSION, GraphFsCommandOutput,
    GraphFsCoreutilsDecision, GraphFsCoreutilsVerb, GraphFsEntry, GraphFsEntryKind, GraphFsFile,
    GraphFsMount, GraphFsOptions, GraphFsPage, GraphFsResolver,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::paging::*;
#[cfg(test)]
use crate::claim::ScopedRead;
#[cfg(test)]
use crate::code_sandbox::SandboxImportClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD};
#[cfg(test)]
use rmpv::Value;
