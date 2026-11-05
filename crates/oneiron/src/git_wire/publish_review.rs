//! Core half of `git_wire::publish_review`: its store-layer items live in `oneiron_store::git_wire::publish_review` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::git_wire::publish_review::*;

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::publish_review_trees::GitTreeReadMode;
use super::{GitOid, GitWire, GitWireFailure, GitWireFailureClass, GitWireOperation, GitWireRepo};
use crate::error::Result;
use std::collections::{BTreeSet, HashMap, HashSet};

impl GitWire<'_> {
    /// Hands `visit` every commit `tip` reaches that no commit of `exclude`
    /// reaches, each before the paths it introduces, page by page. A commit
    /// or tree this store does not hold ends the walk with an error: a
    /// review never stands on part of the history.
    pub fn for_each_review_item(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
        exclude: &[GitOid],
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        self.for_each_review_item_in(repo, tip, exclude, GitTreeReadMode::Captured, visit)
    }

    /// [`Self::for_each_review_item`] with no read bound at all (FIX 7608
    /// slice 2b-i, Rule 5): the same walk, but a page whose listing passes
    /// its bound is read whole through a retained spool, and a commit
    /// reviewed tree by tree reads its trees retained.
    ///
    /// # Errors
    /// A missing commit or tree, a failed read, or `visit`'s own.
    pub fn for_each_review_item_retained(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
        exclude: &[GitOid],
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        self.for_each_review_item_in(repo, tip, exclude, GitTreeReadMode::Retained, visit)
    }

    fn for_each_review_item_in(
        &self,
        repo: &GitWireRepo,
        tip: &GitOid,
        exclude: &[GitOid],
        mode: GitTreeReadMode,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        let mut pending = BTreeSet::from([tip.clone()]);
        let mut page_size = COMMIT_PAGE;
        while !pending.is_empty() {
            let positives: Vec<GitOid> = pending.iter().cloned().collect();
            let argv = FrozenGitArgv::commit_page(&positives, exclude, page_size);
            let listing = match self.run_read_classified(repo, &argv)? {
                Ok(output) => output.stdout,
                Err(failure) if mode == GitTreeReadMode::Retained && past_bound(&failure) => {
                    self.read_spooled(repo, argv.clone())?.read_all()?
                }
                Err(failure)
                    if failure.class() == GitWireFailureClass::OutputOverflow && page_size > 1 =>
                {
                    page_size /= 2;
                    continue;
                }
                Err(failure) => return Err(failure.error(GitWireOperation::ReachableObjects)),
            };
            let page = parse_commit_page(&listing)?;
            if page.is_empty() {
                break;
            }
            // The page is the top of what is left: its parents outside it
            // are the new frontier, and none of them was listed before.
            let inside: HashSet<&GitOid> = page.iter().map(|(commit, _)| commit).collect();
            for (commit, parents) in &page {
                pending.remove(commit);
                for parent in parents {
                    if !inside.contains(parent) {
                        pending.insert(parent.clone());
                    }
                }
            }
            for slice in page.chunks(DIFF_SLICE_COMMITS) {
                self.review_slice(repo, slice, mode, visit)?;
            }
        }
        Ok(())
    }

    /// Diffs one contiguous slice of a page in one call; past a bound, each
    /// half on its own, and one commit through its trees.
    fn review_slice(
        &self,
        repo: &GitWireRepo,
        slice: &[PagedCommit],
        mode: GitTreeReadMode,
        visit: &mut dyn FnMut(GitReviewItem) -> Result<()>,
    ) -> Result<()> {
        let argv = FrozenGitArgv::review_diffs(slice);
        match self.run_read_classified(repo, &argv)? {
            Ok(output) => {
                let mut diffs = parse_diffs(&output.stdout)?;
                for (commit, parents) in slice {
                    visit(GitReviewItem::Commit {
                        commit: commit.clone(),
                        parents: parents.clone(),
                    })?;
                    for item in diffs.remove(commit).unwrap_or_default() {
                        visit(item)?;
                    }
                }
                if !diffs.is_empty() {
                    return Err(invalid("git review diffs named a commit outside the slice"));
                }
                Ok(())
            }
            Err(failure) if past_bound(&failure) => match slice {
                [] => Ok(()),
                [(commit, parents)] => {
                    self.review_commit_by_trees(repo, commit, parents, mode, visit)
                }
                _ => {
                    let (left, right) = slice.split_at(slice.len() / 2);
                    self.review_slice(repo, left, mode, visit)?;
                    self.review_slice(repo, right, mode, visit)
                }
            },
            Err(failure) => Err(failure.error(GitWireOperation::ReviewDiffs)),
        }
    }
}
