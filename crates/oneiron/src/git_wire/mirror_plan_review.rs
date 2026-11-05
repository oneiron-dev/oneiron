//! Core half of `git_wire::mirror_plan_review`: its store-layer items live in `oneiron_store::git_wire::mirror_plan_review` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::git_wire::mirror_plan_review::*;

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::projected_object::tag_header;
use super::publish_review::{COMMIT_PAGE, parse_commit_page};
use super::retained_object::{GitObjectKind, GitRetainedObject};
use super::{GitOid, GitReviewItem, GitWire, GitWireFailureClass, GitWireOperation, GitWireRepo};
use crate::error::Result;
use std::collections::{BTreeSet, HashMap, HashSet};

impl GitWire<'_> {
    /// Peels `tip` through every annotated tag (module docs). A chain that
    /// comes back to a tag it already passed is refused as the loop it is;
    /// an object this store does not hold ends the walk with an error: a
    /// review never stands on part of a ref.
    pub fn peel_ref_tip(&self, repo: &GitWireRepo, tip: &GitOid) -> Result<GitPeeledRef> {
        let mut tags = Vec::new();
        let mut passed = HashSet::new();
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
                "tag" => {
                    if !passed.insert(current.clone()) {
                        return Err(invalid("a pushed ref's tag chain loops"));
                    }
                    let tag = self.read_ref_tag(repo, current)?;
                    current = tag.target.clone();
                    tags.push(tag);
                    continue;
                }
                _ => return Err(invalid("a pushed ref names an object of no known type")),
            };
            return Ok(GitPeeledRef { tags, end });
        }
    }

    /// [`Self::peel_ref_tip`] with every tag read whole through a retained
    /// spool (FIX 7608 slice 2b-i): a tag of any size keeps its whole
    /// payload and its name's stored bytes. Only a real loop or an object
    /// the store lacks ends the walk.
    ///
    /// # Errors
    /// A tag loop, a missing object, or a failed read.
    pub fn peel_ref_tip_retained(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
    ) -> Result<GitRetainedPeeledRef> {
        let mut tags = Vec::new();
        let mut passed = HashSet::new();
        let mut current = tip.clone();
        loop {
            let (kind, _) = self
                .object_kind_and_size(repo, &current)?
                .ok_or_else(|| invalid("a pushed ref names an object this store does not hold"))?;
            let end = match kind {
                GitObjectKind::Commit => GitRefEnd::Commit(current),
                GitObjectKind::Tree => GitRefEnd::Tree(current),
                GitObjectKind::Blob => GitRefEnd::Blob(current),
                GitObjectKind::Tag => {
                    if !passed.insert(current.clone()) {
                        return Err(invalid("a pushed ref's tag chain loops"));
                    }
                    let payload = self.read_object_to_spool(repo, &current)?;
                    let (target, target_kind, name) = tag_header(&payload.read_bytes()?)?;
                    tags.push(GitRetainedRefTag {
                        tag: current,
                        target: target.clone(),
                        target_kind,
                        name,
                        payload,
                    });
                    current = target;
                    continue;
                }
            };
            return Ok(GitRetainedPeeledRef { tags, end });
        }
    }

    /// One tag on a ref's chain: read whole when one read holds it, else
    /// named by its oid and size, its header read for what it names.
    fn read_ref_tag(&self, repo: &GitWireRepo, tag: GitOid) -> Result<GitRefTag> {
        let size = self
            .object_size(repo, &tag)?
            .ok_or_else(|| invalid("a pushed ref names an object this store does not hold"))?;
        let whole =
            usize::try_from(size).is_ok_and(|size| size <= self.process_env.max_output_bytes);
        let raw = if whole {
            self.read_object(repo, &tag)?
        } else {
            self.read_tag_head(repo, &tag)?
        };
        let (target, target_kind, name) = parse_tag_header(&raw)?;
        Ok(GitRefTag {
            tag,
            target,
            target_kind,
            name,
            size,
            raw: whole.then_some(raw),
        })
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

    /// [`Self::for_each_tree_path`] with retained tree reads (FIX 7608
    /// slice 2b-i): the same walk with no width, depth, output or time
    /// bound.
    ///
    /// # Errors
    /// A missing tree, a failed read, or `visit`'s own.
    pub fn for_each_tree_path_retained(
        &self,
        repo: &GitWireRepo,
        tree: &GitOid,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        self.diff_trees_retained(repo, tree, None, visit)
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
