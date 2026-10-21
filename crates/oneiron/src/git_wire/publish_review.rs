//! The full ancestry one exact publish would expose (FIX 6866): every
//! commit the pushed commit reaches that the mirror's tip does not, with all
//! its merge parents, and each path whose entry that commit holds otherwise
//! than one of its parents (a root commit against the empty tree), with the
//! mode and object it holds there. A file added and later deleted or
//! reverted is still named by the commit that added it, so the review is
//! never the tip's diff alone.
//!
//! The walk reads histories of any size in bounded calls, as the LFS census
//! does: commits come in topological pages, each resumed from the frontier
//! the pages before it left, and each slice of a page is diffed in one call.
//! A slice whose diff passes its output or runtime bound splits in half,
//! down to one commit, whose trees are then compared one level at a time.
//! No bound ends the walk, and no blob is skipped for its size: unlike the
//! LFS census's listing, nothing here filters what it names.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::{GitOid, GitWire, GitWireFailure, GitWireFailureClass, GitWireOperation, GitWireRepo};
use crate::error::Result;

/// Commits one topological page lists with their parents. A page whose
/// listing overflows is asked again at half.
const COMMIT_PAGE: usize = 65_536;

/// Commits one diff call covers. A call that overflows or runs out of time
/// splits in half.
const DIFF_SLICE_COMMITS: usize = 512;

/// One thing a reviewed push exposes, in the order the walk meets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitReviewItem {
    /// A commit the mirror's tip does not reach, with every parent.
    Commit {
        commit: GitOid,
        parents: Vec<GitOid>,
    },
    /// One path whose entry the commit before it holds otherwise than one of
    /// its parents: `A`dded, `M`odified, `T`ype-changed or `D`eleted.
    Path {
        status: char,
        /// The entry's mode in octal: the new one, or the deleted one's.
        mode: String,
        /// The object the commit holds there; `None` for a deletion.
        object: Option<GitOid>,
        /// The repo-relative path, as git stores its bytes.
        path: Vec<u8>,
    },
}

/// One commit of a topological page and its parents.
type PagedCommit = (GitOid, Vec<GitOid>);

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
        let mut pending = BTreeSet::from([tip.clone()]);
        let mut page_size = COMMIT_PAGE;
        while !pending.is_empty() {
            let positives: Vec<GitOid> = pending.iter().cloned().collect();
            let argv = FrozenGitArgv::commit_page(&positives, exclude, page_size);
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
                self.review_slice(repo, slice, visit)?;
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
                [(commit, parents)] => self.review_commit_by_trees(repo, commit, parents, visit),
                _ => {
                    let (left, right) = slice.split_at(slice.len() / 2);
                    self.review_slice(repo, left, visit)?;
                    self.review_slice(repo, right, visit)
                }
            },
            Err(failure) => Err(failure.error(GitWireOperation::ReviewDiffs)),
        }
    }
}

/// Whether a failed call passed its output or runtime bound, so a smaller
/// call may finish.
fn past_bound(failure: &GitWireFailure) -> bool {
    matches!(
        failure.class(),
        GitWireFailureClass::OutputOverflow | GitWireFailureClass::Timeout
    )
}

/// A `rev-list --parents` page: each commit with its parents.
fn parse_commit_page(stdout: &[u8]) -> Result<Vec<PagedCommit>> {
    let text = std::str::from_utf8(stdout).map_err(|_| invalid("git commit page must be UTF-8"))?;
    let mut page = Vec::new();
    for line in text.lines() {
        let mut oids = line.split(' ').filter(|field| !field.is_empty());
        let Some(commit) = oids.next() else {
            continue;
        };
        let parents = oids.map(GitOid::parse_hex).collect::<Result<Vec<_>>>()?;
        page.push((GitOid::parse_hex(commit)?, parents));
    }
    Ok(page)
}

/// A `diff-tree --stdin -z --raw` answer: per commit, in the order git
/// printed them, the paths its diffs against each parent named. A commit
/// line is its id alone; an entry is `:<old mode> <new mode> <old> <new>
/// <status>` and then its path, each NUL-terminated.
fn parse_diffs(stdout: &[u8]) -> Result<HashMap<GitOid, Vec<GitReviewItem>>> {
    let mut diffs: HashMap<GitOid, Vec<GitReviewItem>> = HashMap::new();
    let mut current: Option<GitOid> = None;
    let mut fields = stdout.split(|byte| *byte == 0);
    while let Some(field) = fields.next() {
        if field.is_empty() {
            continue;
        }
        let Some(meta) = field.strip_prefix(b":") else {
            let text = std::str::from_utf8(field)
                .map_err(|_| invalid("git review diff commit line must be UTF-8"))?;
            current = Some(GitOid::parse_hex(text.trim())?);
            continue;
        };
        let commit = current
            .clone()
            .ok_or_else(|| invalid("git review diff entry precedes its commit"))?;
        let path = fields
            .next()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| invalid("git review diff entry has no path"))?;
        let meta = std::str::from_utf8(meta)
            .map_err(|_| invalid("git review diff entry must be UTF-8"))?;
        let parts: Vec<&str> = meta.split(' ').collect();
        let [old_mode, new_mode, _old, new, status] = parts.as_slice() else {
            return Err(invalid("git review diff entry is malformed"));
        };
        let status = status
            .chars()
            .next()
            .ok_or_else(|| invalid("git review diff entry has no status"))?;
        let deletion = status == 'D';
        diffs.entry(commit).or_default().push(GitReviewItem::Path {
            status,
            mode: (if deletion { *old_mode } else { *new_mode }).to_owned(),
            object: if deletion {
                None
            } else {
                Some(GitOid::parse_hex(*new)?)
            },
            path: path.to_vec(),
        });
    }
    Ok(diffs)
}
