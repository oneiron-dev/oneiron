//! What a whole ref an automatic mirror plan pushes names beyond the commits
//! it reaches (FIX 6866 part 2), and the two reads a full-auto mirror's green
//! rule needs.
//!
//! A published ref need not name a commit. An annotated tag is its own
//! object, with its own name and message, before what it points at; a ref or
//! a tag may name a tree or a blob directly. [`GitWire::peel_ref_tip`] walks
//! that chain with the existing object reads and hands back every tag on it,
//! raw bytes included, so a review states the tag's own payload instead of
//! pretending the peeled commit stands for it. A tag too large for one read
//! is named by its oid and size, and the walk goes on through what it names:
//! no tag's size and no chain's length holds a ref; only a real loop ends
//! the walk. [`GitWire::for_each_tree_path`]
//! names every path of a tree tip, one tree level a call, as the tree-by-tree
//! review does; nothing is skipped for its size.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::git_wire::failure::GitWireFailureClass;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::projected_object::tag_header;
use crate::git_wire::publish_review::COMMIT_PAGE;
use crate::git_wire::publish_review::GitReviewItem;
use crate::git_wire::publish_review::parse_commit_page;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::retained_object::GitObjectKind;
use crate::git_wire::retained_object::GitRetainedObject;
use oneiron_base::error::Result;

/// Commits one tree read names its trees for.
pub const TREE_READ_BATCH: usize = 4_096;

/// One annotated tag on a ref's way to what it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefTag {
    /// The tag object.
    pub tag: GitOid,
    /// The object it names, and that object's type.
    pub target: GitOid,
    pub target_kind: String,
    /// Its tag name, lossy UTF-8.
    pub name: String,
    /// Its stored size in bytes.
    pub size: u64,
    /// Its raw stored bytes, the header and the message; `None` for a tag
    /// too large to read whole, which a review names by its oid and size.
    pub raw: Option<Vec<u8>>,
}

/// What a ref's chain of tags ends at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRefEnd {
    Commit(GitOid),
    Tree(GitOid),
    Blob(GitOid),
}

/// One ref tip, peeled: the tags on the way and what they end at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPeeledRef {
    pub tags: Vec<GitRefTag>,
    pub end: GitRefEnd,
}

/// One annotated tag on a ref's way to what it names, held whole in a
/// retained spool (FIX 7608 slice 2b-i): no tag is too large to read, and
/// none is named by its size alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRetainedRefTag {
    /// The tag object.
    pub tag: GitOid,
    /// The object it names, and that object's type.
    pub target: GitOid,
    pub target_kind: GitObjectKind,
    /// Its tag name, the stored bytes.
    pub name: Vec<u8>,
    /// Its whole stored payload: header, message and any signature.
    pub payload: GitRetainedObject,
}

/// One ref tip peeled through retained tag reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRetainedPeeledRef {
    pub tags: Vec<GitRetainedRefTag>,
    pub end: GitRefEnd,
}

/// One tag object's header: `object`, `type` and `tag` before the first
/// blank line, as `(target, its type, name)`.
pub fn parse_tag_header(raw: &[u8]) -> Result<(GitOid, String, String)> {
    let header_end = raw
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .unwrap_or(raw.len());
    let header = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let (mut target, mut target_kind, mut name) = (None, None, None);
    for line in header.lines() {
        if let Some(value) = line.strip_prefix("object ") {
            target = Some(GitOid::parse_hex(value)?);
        } else if let Some(value) = line.strip_prefix("type ") {
            target_kind = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("tag ") {
            name = Some(value.to_owned());
        }
    }
    let (Some(target), Some(target_kind)) = (target, target_kind) else {
        return Err(invalid("git tag object names no target"));
    };
    Ok((target, target_kind, name.unwrap_or_default()))
}
