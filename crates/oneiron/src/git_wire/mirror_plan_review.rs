//! What a whole ref an automatic mirror plan pushes names beyond the commits
//! it reaches (FIX 6866 part 2), and the two reads a full-auto mirror's green
//! rule needs.
//!
//! A published ref need not name a commit. An annotated tag is its own
//! object, with its own name and message, before what it points at; a ref or
//! a tag may name a tree or a blob directly. [`GitWire::peel_ref_tip`] walks
//! that chain with the existing object reads and hands back every tag on it,
//! raw bytes included, so a review states the tag's own payload instead of
//! pretending the peeled commit stands for it. [`GitWire::for_each_tree_path`]
//! names every path of a tree tip, one tree level a call, as the tree-by-tree
//! review does; nothing is skipped for its size.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::publish_review::{COMMIT_PAGE, parse_commit_page};
use super::{GitOid, GitReviewItem, GitWire, GitWireFailureClass, GitWireOperation, GitWireRepo};
use crate::error::Result;

/// Tags one chain may hold before the walk refuses it as a loop.
const MAX_TAG_CHAIN: usize = 64;

/// Commits one tree read names its trees for.
const TREE_READ_BATCH: usize = 4_096;

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
    /// Its raw stored bytes: the header and the message.
    pub raw: Vec<u8>,
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

impl GitWire<'_> {
    /// Peels `tip` through every annotated tag, reading each one whole. An
    /// object this store does not hold ends the walk with an error: a review
    /// never stands on part of a ref.
    pub fn peel_ref_tip(&self, repo: &GitWireRepo, tip: &GitOid) -> Result<GitPeeledRef> {
        let mut tags = Vec::new();
        let mut current = tip.clone();
        loop {
            let kinds = self.object_info(repo, std::slice::from_ref(&current))?;
            let kind = kinds
                .get(&current)
                .ok_or_else(|| invalid("a pushed ref names an object this store does not hold"))?;
            let end = match kind.as_str() {
                "commit" => GitRefEnd::Commit(current),
                "tree" => GitRefEnd::Tree(current),
                "blob" => GitRefEnd::Blob(current),
                "tag" if tags.len() < MAX_TAG_CHAIN => {
                    let raw = self.read_object(repo, &current)?;
                    let tag = parse_tag(current, raw)?;
                    current = tag.target.clone();
                    tags.push(tag);
                    continue;
                }
                _ => return Err(invalid("a pushed ref's tag chain does not end")),
            };
            return Ok(GitPeeledRef { tags, end });
        }
    }

    /// Hands `visit` every path of the tree `tree`, as added, one tree level
    /// a call: what a ref naming the tree exposes.
    pub fn for_each_tree_path(
        &self,
        repo: &GitWireRepo,
        tree: &GitOid,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        self.diff_trees(repo, &[], tree, None, visit)
    }

    /// The tree each of `commits` names; a commit this store does not hold
    /// is absent from the map.
    pub fn commit_trees(
        &self,
        repo: &GitWireRepo,
        commits: &[GitOid],
    ) -> Result<HashMap<GitOid, GitOid>> {
        let mut trees = HashMap::new();
        for chunk in commits.chunks(TREE_READ_BATCH) {
            let argv = FrozenGitArgv::object_info_peeled(chunk, "^{tree}");
            let output = self.run_read(repo, &argv)?;
            let text = String::from_utf8_lossy(&output.stdout);
            let mut lines = text.lines();
            for commit in chunk {
                let line = lines
                    .next()
                    .ok_or_else(|| invalid("git tree read answered too few names"))?;
                let mut fields = line.split(' ');
                if let (Some(oid), Some("tree")) = (fields.next(), fields.next()) {
                    trees.insert(commit.clone(), GitOid::parse_hex(oid)?);
                }
            }
        }
        Ok(trees)
    }

    /// The first commit of `listed` that `tip` reaches, walking its history
    /// newest first (topological order, every parent) in bounded pages:
    /// none of `listed` it reaches descends from the one returned. `None`
    /// when `tip` reaches none of them.
    pub fn newest_listed_ancestor(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
        listed: &HashSet<GitOid>,
    ) -> Result<Option<GitOid>> {
        if listed.is_empty() {
            return Ok(None);
        }
        let mut pending = BTreeSet::from([tip.clone()]);
        let mut page_size = COMMIT_PAGE;
        while !pending.is_empty() {
            let positives: Vec<GitOid> = pending.iter().cloned().collect();
            let argv = FrozenGitArgv::commit_page(&positives, &[], page_size);
            let output = match self.run_read_classified(repo, &argv)? {
                Ok(output) => output,
                Err(failure)
                    if failure.class() == GitWireFailureClass::OutputOverflow && page_size > 1 =>
                {
                    page_size /= 2;
                    continue;
                }
                Err(failure) => return Err(failure.error(GitWireOperation::ReachableObjects)),
            };
            let page = parse_commit_page(&output.stdout)?;
            if page.is_empty() {
                break;
            }
            if let Some((found, _)) = page.iter().find(|(commit, _)| listed.contains(commit)) {
                return Ok(Some(found.clone()));
            }
            let inside: HashSet<&GitOid> = page.iter().map(|(commit, _)| commit).collect();
            for (commit, parents) in &page {
                pending.remove(commit);
                for parent in parents {
                    if !inside.contains(parent) {
                        pending.insert(parent.clone());
                    }
                }
            }
        }
        Ok(None)
    }
}

/// One tag object's header: `object`, `type` and `tag` before the first
/// blank line.
fn parse_tag(tag: GitOid, raw: Vec<u8>) -> Result<GitRefTag> {
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
    Ok(GitRefTag {
        tag,
        target,
        target_kind,
        name: name.unwrap_or_default(),
        raw,
    })
}
