//! The tree-by-tree half of an exact publish's review (FIX 6866): one
//! commit whose diff alone passed its output or runtime bound is compared
//! against each parent (the empty tree, for a root) one tree level per
//! call, descending only into trees that differ. It names what the one
//! diff call would have, so the review never stops for a commit's size.

use std::collections::BTreeMap;

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::{GitOid, GitReviewItem, GitTreeEntry, GitWire, GitWireRepo};
use crate::error::Result;

/// The tree entry mode of a tree.
const TREE_MODE: u32 = 0o040_000;

/// The mode bits that name an entry's type.
const TYPE_BITS: u32 = 0o170_000;

impl GitWire<'_> {
    /// One commit whose diff alone passed a bound, compared against each
    /// parent (the empty tree, for a root) one tree level per call.
    pub(super) fn review_commit_by_trees(
        &self,
        repo: &GitWireRepo,
        commit: &GitOid,
        parents: &[GitOid],
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        visit(GitReviewItem::Commit {
            commit: commit.clone(),
            parents: parents.to_vec(),
        })?;
        let tree = self.commit_tree(repo, commit)?;
        if parents.is_empty() {
            return self.diff_trees(repo, &[], &tree, None, visit);
        }
        for parent in parents {
            let old = self.commit_tree(repo, parent)?;
            self.diff_trees(repo, &[], &tree, Some(&old), visit)?;
        }
        Ok(())
    }

    /// The tree a commit names.
    fn commit_tree(&self, repo: &GitWireRepo, commit: &GitOid) -> Result<GitOid> {
        let argv = FrozenGitArgv::object_info_peeled(std::slice::from_ref(commit), "^{tree}");
        let output = self.run_read(repo, &argv)?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mut fields = text.lines().next().unwrap_or_default().split(' ');
        match (fields.next(), fields.next()) {
            (Some(oid), Some("tree")) => GitOid::parse_hex(oid),
            _ => Err(invalid("a reviewed commit's tree is not in this store")),
        }
    }

    /// Every path under `prefix` whose entry `new` holds otherwise than
    /// `old` (`None`: the empty tree), descending only into trees that differ.
    pub(super) fn diff_trees(
        &self,
        repo: &GitWireRepo,
        prefix: &[u8],
        new: &GitOid,
        old: Option<&GitOid>,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        let mut before: BTreeMap<Vec<u8>, GitTreeEntry> = match old {
            Some(old) => self
                .read_tree(repo, old)?
                .into_iter()
                .map(|entry| (entry.name.clone(), entry))
                .collect(),
            None => BTreeMap::new(),
        };
        for entry in self.read_tree(repo, new)? {
            let prior = before.remove(&entry.name);
            if prior
                .as_ref()
                .is_some_and(|prior| prior.oid == entry.oid && prior.mode == entry.mode)
            {
                continue;
            }
            let path = joined(prefix, &entry.name);
            let prior_tree = prior.as_ref().filter(|prior| prior.mode == TREE_MODE);
            if entry.mode == TREE_MODE {
                if let Some(prior) = prior.as_ref().filter(|prior| prior.mode != TREE_MODE) {
                    visit(deleted(prior, path.clone()))?;
                }
                self.diff_trees(
                    repo,
                    &path,
                    &entry.oid,
                    prior_tree.map(|tree| &tree.oid),
                    visit,
                )?;
                continue;
            }
            if let Some(prior) = prior_tree {
                visit(deleted(prior, path.clone()))?;
            }
            let status = match prior.as_ref() {
                None => 'A',
                Some(prior) if prior.mode == TREE_MODE => 'A',
                Some(prior) if (prior.mode ^ entry.mode) & TYPE_BITS != 0 => 'T',
                Some(_) => 'M',
            };
            visit(GitReviewItem::Path {
                status,
                mode: format!("{:06o}", entry.mode),
                object: Some(entry.oid),
                path,
            })?;
        }
        for (name, prior) in before {
            visit(deleted(&prior, joined(prefix, &name)))?;
        }
        Ok(())
    }
}

/// The deletion of `prior` at `path`. A deleted tree is named once.
fn deleted(prior: &GitTreeEntry, path: Vec<u8>) -> GitReviewItem {
    GitReviewItem::Path {
        status: 'D',
        mode: format!("{:06o}", prior.mode),
        object: None,
        path,
    }
}

/// `prefix/name`, or `name` at the root.
fn joined(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = prefix.to_vec();
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}
