//! Byte-preserving projection of complete Git trees. No worktree IO or ref writes.
use crate::git_wire::ids::GitOid;
use crate::git_wire::repo::GitWireRepo;
use crate::scan_kind::EngineScan;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use std::collections::BTreeMap;

/// One file's bytes a tree read holds in memory: a machine floor.
pub const MAX_TREE_FILE_BYTES: usize = 32 * 1024 * 1024;
/// One tree's file bytes a read holds in memory at once: a machine floor.
pub const MAX_TREE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginTreeFile {
    pub mode: u32,
    pub content: Vec<u8>,
}
