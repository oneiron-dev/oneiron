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

/// How a review walk reads trees (FIX 7608 slice 2b-i).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GitTreeReadMode {
    /// One captured `ls-tree` per tree under the process bounds, one call
    /// frame per level: today's walk.
    Captured,
    /// Each tree's listing spooled whole and read record by record, its
    /// levels on a heap stack: no output, time or depth bound (Rule 5).
    Retained,
}

/// One tree level of a retained walk: what is left of the new tree's
/// entries, and the old tree's entries not yet matched.
struct TreeFrame {
    prefix: Vec<u8>,
    entries: std::vec::IntoIter<GitTreeEntry>,
    before: BTreeMap<Vec<u8>, GitTreeEntry>,
}

impl GitWire<'_> {
    /// One commit whose diff alone passed a bound, compared against each
    /// parent (the empty tree, for a root) one tree level per call, its
    /// trees read as `mode` says.
    pub(super) fn review_commit_by_trees(
        &self,
        repo: &GitWireRepo,
        commit: &GitOid,
        parents: &[GitOid],
        mode: GitTreeReadMode,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        visit(GitReviewItem::Commit {
            commit: commit.clone(),
            parents: parents.to_vec(),
        })?;
        let tree = self.commit_tree(repo, commit)?;
        if parents.is_empty() {
            return self.diff_trees_in(repo, &tree, None, mode, visit);
        }
        for parent in parents {
            let old = self.commit_tree(repo, parent)?;
            self.diff_trees_in(repo, &tree, Some(&old), mode, visit)?;
        }
        Ok(())
    }

    /// [`Self::diff_trees`] from the root, its trees read as `mode` says.
    pub(super) fn diff_trees_in(
        &self,
        repo: &GitWireRepo,
        new: &GitOid,
        old: Option<&GitOid>,
        mode: GitTreeReadMode,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        match mode {
            GitTreeReadMode::Captured => self.diff_trees(repo, &[], new, old, visit),
            GitTreeReadMode::Retained => self.diff_trees_retained(repo, new, old, visit),
        }
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

    /// [`Self::diff_trees`] from the root with retained tree reads (FIX
    /// 7608 slice 2b-i): the same paths in the same order, each level a
    /// heap frame instead of a call, each listing spooled whole, each path
    /// its stored bytes. No width, depth, output or time bound ends it.
    pub(super) fn diff_trees_retained(
        &self,
        repo: &GitWireRepo,
        new: &GitOid,
        old: Option<&GitOid>,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        let mut frames = vec![self.tree_frame(repo, Vec::new(), new, old)?];
        loop {
            let Some(frame) = frames.last_mut() else {
                return Ok(());
            };
            let Some(entry) = frame.entries.next() else {
                if let Some(done) = frames.pop() {
                    for (name, prior) in done.before {
                        visit(deleted(&prior, joined(&done.prefix, &name)))?;
                    }
                }
                continue;
            };
            let prior = frame.before.remove(&entry.name);
            if prior
                .as_ref()
                .is_some_and(|prior| prior.oid == entry.oid && prior.mode == entry.mode)
            {
                continue;
            }
            let path = joined(&frame.prefix, &entry.name);
            let prior_tree = prior.as_ref().filter(|prior| prior.mode == TREE_MODE);
            if entry.mode == TREE_MODE {
                if let Some(prior) = prior.as_ref().filter(|prior| prior.mode != TREE_MODE) {
                    visit(deleted(prior, path.clone()))?;
                }
                let child =
                    self.tree_frame(repo, path, &entry.oid, prior_tree.map(|tree| &tree.oid))?;
                frames.push(child);
                continue;
            }
            if let Some(prior) = prior_tree {
                visit(deleted(prior, path.clone()))?;
            }
            visit(GitReviewItem::Path {
                status: path_status(prior.as_ref(), &entry),
                mode: format!("{:06o}", entry.mode),
                object: Some(entry.oid),
                path,
            })?;
        }
    }

    /// One level of a retained walk: `new`'s entries in order, `old`'s by
    /// name.
    fn tree_frame(
        &self,
        repo: &GitWireRepo,
        prefix: Vec<u8>,
        new: &GitOid,
        old: Option<&GitOid>,
    ) -> Result<TreeFrame> {
        let mut before = BTreeMap::new();
        if let Some(old) = old {
            self.for_each_tree_entry_retained(repo, old, &mut |entry| {
                before.insert(entry.name.clone(), entry);
                Ok(())
            })?;
        }
        let mut entries = Vec::new();
        self.for_each_tree_entry_retained(repo, new, &mut |entry| {
            entries.push(entry);
            Ok(())
        })?;
        Ok(TreeFrame {
            prefix,
            entries: entries.into_iter(),
            before,
        })
    }
}

/// The status a changed non-tree entry gets against what its path held.
fn path_status(prior: Option<&GitTreeEntry>, entry: &GitTreeEntry) -> char {
    match prior {
        None => 'A',
        Some(prior) if prior.mode == TREE_MODE => 'A',
        Some(prior) if (prior.mode ^ entry.mode) & TYPE_BITS != 0 => 'T',
        Some(_) => 'M',
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
