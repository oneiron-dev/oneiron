//! The tree-by-tree half of an exact publish's review (FIX 6866): one
//! commit whose diff alone passed its output or runtime bound is compared
//! against each parent (the empty tree, for a root) one tree level per
//! call, descending only into trees that differ. It names what the one
//! diff call would have, so the review never stops for a commit's size.

use std::collections::BTreeMap;

use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::objects::GitTreeEntry;
use crate::git_wire::publish_review::GitReviewItem;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// The tree entry mode of a tree.
pub const TREE_MODE: u32 = 0o040_000;

/// The mode bits that name an entry's type.
pub const TYPE_BITS: u32 = 0o170_000;

/// How a review walk reads trees (FIX 7608 slice 2b-i).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitTreeReadMode {
    /// One captured `ls-tree` per tree under the process bounds, one call
    /// frame per level: today's walk.
    Captured,
    /// Each tree's listing spooled whole and read record by record, its
    /// levels on a heap stack: no output, time or depth bound (Rule 5).
    Retained,
}

/// One tree level of a retained walk: what is left of the new tree's
/// entries, and the old tree's entries not yet matched.
pub struct TreeFrame {
    pub prefix: Vec<u8>,
    pub entries: std::vec::IntoIter<GitTreeEntry>,
    pub before: BTreeMap<Vec<u8>, GitTreeEntry>,
}

/// The status a changed non-tree entry gets against what its path held.
pub fn path_status(prior: Option<&GitTreeEntry>, entry: &GitTreeEntry) -> char {
    match prior {
        None => 'A',
        Some(prior) if prior.mode == TREE_MODE => 'A',
        Some(prior) if (prior.mode ^ entry.mode) & TYPE_BITS != 0 => 'T',
        Some(_) => 'M',
    }
}

/// The deletion of `prior` at `path`. A deleted tree is named once.
pub fn deleted(prior: &GitTreeEntry, path: Vec<u8>) -> GitReviewItem {
    GitReviewItem::Path {
        status: 'D',
        mode: format!("{:06o}", prior.mode),
        object: None,
        path,
    }
}

/// `prefix/name`, or `name` at the root.
pub fn joined(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = prefix.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}
