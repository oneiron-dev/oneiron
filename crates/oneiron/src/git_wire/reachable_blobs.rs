//! The small blobs a set of tips reaches through its whole history, read in
//! bounded batches: what a caller looking for Git-LFS pointers needs, past
//! the tip trees and across every ref it names.
//!
//! A history whose reachable listing fits one call is read in that call. A
//! larger one is read in pages (FIX 6331), every call inside GitWire's own
//! output and runtime bounds, and no bound ends the walk. Commits come in
//! topological pages, each resumed from the frontier the pages before it
//! left; a page that overflows or runs out of time is asked again at half
//! (FIX 6393). Each slice of a page lists the objects its commits reach apart
//! from what their parents outside the slice reach. A slice whose listing
//! still overflows or runs out of time splits in half, down to one commit's
//! tree and then that tree's entries, read in pages when one listing of
//! them passes the bounds.

use std::collections::{BTreeSet, HashSet};

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::objects::parse_tree_entries;
use super::{
    GitOid, GitTreeEntry, GitWire, GitWireFailure, GitWireFailureClass, GitWireOperation,
    GitWireRepo, GitWireResult,
};
use crate::error::Result;

/// Oids one `cat-file --batch-check` child sizes. Its answer, under a
/// hundred bytes an object, stays far inside the default output bound.
const SIZE_BATCH_OIDS: usize = 65_536;

/// Blob bytes one `cat-file --batch` child reads; the next blob goes to the
/// next child.
const READ_BATCH_BYTES: u64 = 4 * 1024 * 1024;

/// Commits one topological page lists with their parents, about eighty
/// bytes a commit. A page whose listing overflows is asked again at half.
const COMMIT_PAGE: usize = 65_536;

/// Commits whose objects one reachable-objects call lists. A call that
/// overflows or runs out of time splits in half.
const OBJECT_SLICE_COMMITS: usize = 2_048;

/// Direct entries of one tree the walk takes at a time, the oids one size
/// batch carries.
const TREE_PAGE_ENTRIES: usize = SIZE_BATCH_OIDS;

/// The tree entry mode of a tree.
const TREE_MODE: u32 = 0o040_000;

/// The tree entry mode of a submodule's commit, which this store does not
/// hold.
const GITLINK_MODE: u32 = 0o160_000;

/// A tip, and the object it peels to through every tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPeeledTip {
    /// The tip as named.
    pub tip: GitOid,
    /// The object it peels to, with that object's type; `None` when this
    /// store does not hold it.
    pub peeled: Option<(GitOid, String)>,
}

impl GitPeeledTip {
    /// The commit this tip peels to, if it peels to one.
    pub fn commit(&self) -> Option<&GitOid> {
        self.peeled
            .as_ref()
            .filter(|(_, kind)| kind == "commit")
            .map(|(oid, _)| oid)
    }
}

/// One commit of a topological page and its parents.
type PagedCommit = (GitOid, Vec<GitOid>);

impl GitWire<'_> {
    /// Hands `visit` the bytes of each distinct blob smaller than
    /// `below_bytes` that `tips` reach, through every commit, tree and tag of
    /// their history, in the order git walks them, from one reachable-objects
    /// call. `Ok(Ok(false))` when the walk met an object this store does not
    /// hold, so part of the graph went unread; every blob it could read is
    /// still visited. `Ok(Err(class))` when that one call passed its output
    /// bound ([`GitWireFailureClass::OutputOverflow`]) or its runtime bound
    /// ([`GitWireFailureClass::Timeout`]): nothing was visited, and
    /// [`for_each_reachable_blob_below_paged`] reads the same history in
    /// pages.
    ///
    /// [`for_each_reachable_blob_below_paged`]: Self::for_each_reachable_blob_below_paged
    pub fn for_each_reachable_blob_below(
        &self,
        repo: &GitWireRepo,
        tips: &[GitOid],
        below_bytes: u64,
        mut visit: impl FnMut(&GitOid, &[u8]),
    ) -> GitWireResult<std::result::Result<bool, GitWireFailureClass>> {
        let mut distinct = HashSet::new();
        let tips: Vec<GitOid> = tips
            .iter()
            .filter(|oid| distinct.insert(*oid))
            .cloned()
            .collect();
        if tips.is_empty() {
            return Ok(Ok(true));
        }
        let argv = FrozenGitArgv::reachable_objects_below(&tips, &[], below_bytes);
        let listing = match self.run_read_classified(repo, &argv)? {
            Ok(output) => output,
            Err(failure) if past_bound(&failure) => return Ok(Err(failure.class())),
            Err(failure) => return Err(failure.error(GitWireOperation::ReachableObjects)),
        };
        let (reached, complete) = parse_listing(&listing.stdout)?;
        let read = self.visit_small_blobs(repo, &reached, below_bytes, &mut visit)?;
        Ok(Ok(complete && read))
    }

    /// Peels each tip through its tags, in bounded batches.
    pub fn peel_tips(
        &self,
        repo: &GitWireRepo,
        tips: &[GitOid],
    ) -> GitWireResult<Vec<GitPeeledTip>> {
        let mut peeled = Vec::with_capacity(tips.len());
        for chunk in tips.chunks(SIZE_BATCH_OIDS) {
            let output = self.run_read(repo, &FrozenGitArgv::object_info_peeled(chunk, "^{}"))?;
            let answers = parse_peeled(&output.stdout)?;
            if answers.len() != chunk.len() {
                return Err(invalid("git peel answered another number of names"));
            }
            for (tip, answer) in chunk.iter().zip(answers) {
                peeled.push(GitPeeledTip {
                    tip: tip.clone(),
                    peeled: answer,
                });
            }
        }
        Ok(peeled)
    }

    /// Whether `tips` reach every commit in `commits`.
    pub fn commits_reachable_from(
        &self,
        repo: &GitWireRepo,
        commits: &[GitOid],
        tips: &[GitOid],
    ) -> GitWireResult<bool> {
        if commits.is_empty() {
            return Ok(true);
        }
        let output = self.run_read(repo, &FrozenGitArgv::commits_outside(commits, tips))?;
        Ok(output.stdout.iter().all(u8::is_ascii_whitespace))
    }

    /// Hands `visit` the bytes of each blob smaller than `below_bytes` that
    /// `tips` reach and the commits `walked` names do not, reading in pages
    /// so that no call passes GitWire's output or runtime bound. A tree or
    /// blob tip `walked` names was read before as well. A blob two pages
    /// reach may be visited twice. `Ok(false)` when part of the graph could
    /// not be read: a tip or object this store does not hold.
    pub fn for_each_reachable_blob_below_paged(
        &self,
        repo: &GitWireRepo,
        tips: &[GitPeeledTip],
        walked: &[GitOid],
        below_bytes: u64,
        mut visit: impl FnMut(&GitOid, &[u8]),
    ) -> GitWireResult<bool> {
        let mut complete = true;
        let mut pending = BTreeSet::new();
        let mut loose_trees = Vec::new();
        let mut loose_blobs = Vec::new();
        for tip in tips {
            let Some((oid, kind)) = &tip.peeled else {
                complete = false;
                continue;
            };
            match kind.as_str() {
                "commit" => {
                    pending.insert(oid.clone());
                }
                _ if walked.contains(&tip.tip) => {}
                "tree" => loose_trees.push(oid.clone()),
                "blob" => loose_blobs.push(oid.clone()),
                _ => complete = false,
            }
        }
        complete &= self.visit_small_blobs(repo, &loose_blobs, below_bytes, &mut visit)?;
        if !loose_trees.is_empty() {
            complete &= self.walk_trees(repo, &loose_trees, &[], below_bytes, &mut visit)?;
        }
        let mut page_size = COMMIT_PAGE;
        while !pending.is_empty() {
            let positives: Vec<GitOid> = pending.iter().cloned().collect();
            let argv = FrozenGitArgv::commit_page(&positives, walked, page_size);
            let output = match self.run_read_classified(repo, &argv)? {
                Ok(output) => output,
                Err(failure) if past_bound(&failure) && page_size > 1 => {
                    page_size /= 2;
                    continue;
                }
                Err(failure) => return Err(failure.error(GitWireOperation::ReachableObjects)),
            };
            let page = parse_commit_page(&output.stdout)?;
            if page.is_empty() {
                break;
            }
            // The page is the top of what is left: none of its parents was
            // walked before, so the parents outside it are the new frontier.
            let inside: HashSet<&GitOid> = page.iter().map(|(commit, _)| commit).collect();
            for (commit, parents) in &page {
                pending.remove(commit);
                for parent in parents {
                    if !inside.contains(parent) {
                        pending.insert(parent.clone());
                    }
                }
            }
            for slice in page.chunks(OBJECT_SLICE_COMMITS) {
                complete &= self.walk_commit_slice(repo, slice, below_bytes, &mut visit)?;
            }
        }
        Ok(complete)
    }

    /// Lists and reads what one contiguous slice of a topological page
    /// reaches apart from its parents outside the slice; on an overflow or a
    /// timeout, each half on its own, and one commit through its tree.
    fn walk_commit_slice(
        &self,
        repo: &GitWireRepo,
        slice: &[PagedCommit],
        below_bytes: u64,
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        let inside: HashSet<&GitOid> = slice.iter().map(|(commit, _)| commit).collect();
        let commits: Vec<GitOid> = slice.iter().map(|(commit, _)| commit.clone()).collect();
        let boundary: Vec<GitOid> = slice
            .iter()
            .flat_map(|(_, parents)| parents)
            .filter(|parent| !inside.contains(parent))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let argv = FrozenGitArgv::reachable_objects_below(&commits, &boundary, below_bytes);
        match self.run_read_classified(repo, &argv)? {
            Ok(output) => {
                let (reached, complete) = parse_listing(&output.stdout)?;
                Ok(self.visit_small_blobs(repo, &reached, below_bytes, visit)? && complete)
            }
            Err(failure) if past_bound(&failure) => match slice {
                [] => Ok(true),
                [(commit, parents)] => {
                    let output = self.run_read(
                        repo,
                        &FrozenGitArgv::object_info_peeled(std::slice::from_ref(commit), "^{tree}"),
                    )?;
                    match parse_peeled(&output.stdout)?.pop().flatten() {
                        Some((tree, kind)) if kind == "tree" => {
                            self.walk_trees(repo, &[tree], parents, below_bytes, visit)
                        }
                        _ => Ok(false),
                    }
                }
                _ => {
                    let (left, right) = slice.split_at(slice.len() / 2);
                    let left = self.walk_commit_slice(repo, left, below_bytes, visit)?;
                    let right = self.walk_commit_slice(repo, right, below_bytes, visit)?;
                    Ok(left && right)
                }
            },
            Err(failure) => Err(failure.error(GitWireOperation::ReachableObjects)),
        }
    }

    /// Lists and reads what `trees` reach apart from what the `exclude`
    /// commits reach; on an overflow or a timeout, each half on its own, and
    /// one tree through its entries.
    fn walk_trees(
        &self,
        repo: &GitWireRepo,
        trees: &[GitOid],
        exclude: &[GitOid],
        below_bytes: u64,
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        let argv = FrozenGitArgv::reachable_objects_below(trees, exclude, below_bytes);
        match self.run_read_classified(repo, &argv)? {
            Ok(output) => {
                let (reached, complete) = parse_listing(&output.stdout)?;
                Ok(self.visit_small_blobs(repo, &reached, below_bytes, visit)? && complete)
            }
            Err(failure) if past_bound(&failure) => match trees {
                [] => Ok(true),
                [tree] => {
                    let mut complete = true;
                    self.read_tree_paged(repo, tree, &mut |entries| {
                        let mut subtrees = Vec::new();
                        let mut blobs = Vec::new();
                        for entry in entries {
                            match entry.mode {
                                TREE_MODE => subtrees.push(entry.oid.clone()),
                                GITLINK_MODE => {}
                                _ => blobs.push(entry.oid.clone()),
                            }
                        }
                        complete &=
                            self.visit_small_blobs(repo, &blobs, below_bytes, &mut *visit)?;
                        if !subtrees.is_empty() {
                            complete &= self.walk_trees(
                                repo,
                                &subtrees,
                                exclude,
                                below_bytes,
                                &mut *visit,
                            )?;
                        }
                        Ok(())
                    })?;
                    Ok(complete)
                }
                _ => {
                    let (left, right) = trees.split_at(trees.len() / 2);
                    let left = self.walk_trees(repo, left, exclude, below_bytes, visit)?;
                    let right = self.walk_trees(repo, right, exclude, below_bytes, visit)?;
                    Ok(left && right)
                }
            },
            Err(failure) => Err(failure.error(GitWireOperation::ReachableObjects)),
        }
    }

    /// Hands `visit_page` the direct entries of one tree, in pages of at most
    /// [`TREE_PAGE_ENTRIES`] in tree order (FIX 6393). A listing inside the
    /// per-call bounds is read in one call; one past them is spooled whole
    /// and parsed one range at a time
    /// ([`Self::for_each_tree_entry_retained`], Rule 5), so no tree is too
    /// wide to walk.
    fn read_tree_paged(
        &self,
        repo: &GitWireRepo,
        tree: &GitOid,
        visit_page: &mut dyn FnMut(&[GitTreeEntry]) -> Result<()>,
    ) -> Result<()> {
        let argv = FrozenGitArgv::read_tree(tree);
        match self.run_read_classified(repo, &argv)? {
            Ok(output) => {
                for page in parse_tree_entries(&output.stdout)?.chunks(TREE_PAGE_ENTRIES) {
                    visit_page(page)?;
                }
                return Ok(());
            }
            Err(failure) if past_bound(&failure) => {}
            Err(failure) => return Err(failure.error(argv.operation())),
        }
        let mut page = Vec::new();
        self.for_each_tree_entry_retained(repo, tree, &mut |entry| {
            page.push(entry);
            if page.len() >= TREE_PAGE_ENTRIES {
                visit_page(page.as_slice())?;
                page.clear();
            }
            Ok(())
        })?;
        if !page.is_empty() {
            visit_page(page.as_slice())?;
        }
        Ok(())
    }

    /// Sizes `reached` in bounded batches and reads each blob smaller than
    /// `below_bytes` into `visit`, in order. `Ok(false)` when one was gone.
    fn visit_small_blobs(
        &self,
        repo: &GitWireRepo,
        reached: &[GitOid],
        below_bytes: u64,
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        let mut complete = true;
        let mut batch = Vec::new();
        let mut batch_bytes = 0_u64;
        for chunk in reached.chunks(SIZE_BATCH_OIDS) {
            let output = self.run_read(repo, &FrozenGitArgv::object_info(chunk))?;
            for (oid, sized) in parse_object_sizes(&output.stdout)? {
                let Some((kind, size)) = sized else {
                    complete = false;
                    continue;
                };
                if kind != "blob" || size >= below_bytes {
                    continue;
                }
                if !batch.is_empty() && batch_bytes.saturating_add(size) > READ_BATCH_BYTES {
                    complete &= self.read_blob_batch(repo, &batch, visit)?;
                    batch.clear();
                    batch_bytes = 0;
                }
                batch_bytes = batch_bytes.saturating_add(size);
                batch.push(oid);
            }
        }
        if !batch.is_empty() {
            complete &= self.read_blob_batch(repo, &batch, visit)?;
        }
        Ok(complete)
    }

    /// Hands `visit` each object `oids` names, in order and with its index
    /// (FIX 7229): one size call, then one `cat-file --batch` child for each
    /// bounded batch of bytes, never two children an object. Each must be
    /// a `kind` object (`blob` or `tree`). `visit` answers whether to read
    /// on; `Ok(false)` when it stopped the read.
    ///
    /// # Errors
    /// An object this store does not hold as a `kind`, a failed read, or an
    /// error `visit` answered.
    pub fn read_objects_in_order(
        &self,
        repo: &GitWireRepo,
        oids: &[GitOid],
        kind: &str,
        visit: &mut dyn FnMut(usize, &[u8]) -> Result<bool>,
    ) -> Result<bool> {
        let mut sizes = Vec::with_capacity(oids.len());
        for chunk in oids.chunks(SIZE_BATCH_OIDS) {
            let output = self.run_read(repo, &FrozenGitArgv::object_info(chunk))?;
            for (_, sized) in parse_object_sizes(&output.stdout)? {
                match sized {
                    Some((found, size)) if found == kind => sizes.push(size),
                    _ => {
                        return Err(invalid(
                            "git object is not of the asked type in this object store",
                        ));
                    }
                }
            }
        }
        if sizes.len() != oids.len() {
            return Err(invalid("git object sizes do not answer every blob"));
        }
        let mut start = 0;
        while start < oids.len() {
            let mut end = start + 1;
            let mut bytes = sizes[start];
            while end < oids.len() && bytes.saturating_add(sizes[end]) <= READ_BATCH_BYTES {
                bytes = bytes.saturating_add(sizes[end]);
                end += 1;
            }
            let output = self.run_read(repo, &FrozenGitArgv::read_objects(&oids[start..end]))?;
            let (mut next, mut stopped, mut failed) = (start, false, None);
            let complete = parse_batch_objects(&output.stdout, &mut |oid, found, body| {
                if stopped || failed.is_some() {
                    return;
                }
                if oids.get(next) != Some(oid) || found != kind {
                    failed = Some(invalid("git batch answered another object"));
                    return;
                }
                match visit(next, body) {
                    Ok(true) => {}
                    Ok(false) => stopped = true,
                    Err(error) => failed = Some(error),
                }
                next += 1;
            })?;
            if let Some(error) = failed {
                return Err(error);
            }
            if stopped {
                return Ok(false);
            }
            if !complete || next != end {
                return Err(invalid("git batch did not answer every blob"));
            }
            start = end;
        }
        Ok(true)
    }

    /// Reads each of `oids` that is a blob into `visit`, sized and read in
    /// bounded batches: a few `cat-file` children for a whole tree's files,
    /// never two a file (FIX 6946). `Ok(false)` when one was gone.
    pub(crate) fn read_blobs(
        &self,
        repo: &GitWireRepo,
        oids: &[GitOid],
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        self.visit_small_blobs(repo, oids, u64::MAX, visit)
    }

    /// Reads one batch of blobs into `visit`; `Ok(false)` when one was gone.
    fn read_blob_batch(
        &self,
        repo: &GitWireRepo,
        oids: &[GitOid],
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        let output = self.run_read(repo, &FrozenGitArgv::read_objects(oids))?;
        parse_batch_objects(&output.stdout, &mut |oid, kind, body| {
            if kind == "blob" {
                visit(oid, body);
            }
        })
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

/// A `rev-list --objects --no-object-names --missing=print` listing: the
/// oids it reached, and whether it met no missing object.
fn parse_listing(stdout: &[u8]) -> Result<(Vec<GitOid>, bool)> {
    let mut complete = true;
    let mut reached = Vec::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.first() == Some(&b'?') {
            complete = false;
            continue;
        }
        let text =
            std::str::from_utf8(line).map_err(|_| invalid("git object listing must be UTF-8"))?;
        reached.push(GitOid::parse_hex(text)?);
    }
    Ok((reached, complete))
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

/// `cat-file --batch-check` answers to peeled names, one a line in order:
/// the object and its type, or `None` when the name is missing.
fn parse_peeled(stdout: &[u8]) -> Result<Vec<Option<(GitOid, String)>>> {
    let text = std::str::from_utf8(stdout).map_err(|_| invalid("git peel answer must be UTF-8"))?;
    let mut answers = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(' ');
        let name = fields.next().unwrap_or_default();
        let answer = match (fields.next(), fields.next()) {
            (Some("missing"), None) => None,
            (Some(kind), Some(_)) => Some((GitOid::parse_hex(name)?, kind.to_owned())),
            _ => return Err(invalid("git peel answer is malformed")),
        };
        answers.push(answer);
    }
    Ok(answers)
}

/// `cat-file --batch-check` lines: each oid with its type and size, or
/// `None` when the store does not hold it.
fn parse_object_sizes(stdout: &[u8]) -> Result<Vec<(GitOid, Option<(String, u64)>)>> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| invalid("git object sizes must be UTF-8"))?;
    let mut sized = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(' ');
        let oid = GitOid::parse_hex(fields.next().unwrap_or_default())?;
        let entry = match (fields.next(), fields.next()) {
            (Some("missing"), None) => None,
            (Some(kind), Some(size)) => Some((
                kind.to_owned(),
                size.parse::<u64>()
                    .map_err(|_| invalid("git object size is not a number"))?,
            )),
            _ => return Err(invalid("git object size line is malformed")),
        };
        sized.push((oid, entry));
    }
    Ok(sized)
}

/// Walks `cat-file --batch` output, handing each object's type and bytes
/// to `visit`. `Ok(false)` when an object was missing.
fn parse_batch_objects(
    mut rest: &[u8],
    visit: &mut impl FnMut(&GitOid, &str, &[u8]),
) -> Result<bool> {
    let mut complete = true;
    while let Some(end) = rest.iter().position(|byte| *byte == b'\n') {
        let (header, after) = rest.split_at(end);
        let after = after.get(1..).unwrap_or_default();
        let header =
            std::str::from_utf8(header).map_err(|_| invalid("git batch header must be UTF-8"))?;
        let mut fields = header.split(' ');
        let oid = GitOid::parse_hex(fields.next().unwrap_or_default())?;
        let (kind, size) = match (fields.next(), fields.next()) {
            (Some("missing"), None) => {
                complete = false;
                rest = after;
                continue;
            }
            (Some(kind), Some(size)) => (
                kind,
                size.parse::<usize>()
                    .map_err(|_| invalid("git batch object size is not a number"))?,
            ),
            _ => return Err(invalid("git batch header is malformed")),
        };
        let Some((body, tail)) = after.split_at_checked(size) else {
            return Err(invalid("git batch object is truncated"));
        };
        let Some(tail) = tail.strip_prefix(b"\n") else {
            return Err(invalid("git batch object is not terminated"));
        };
        visit(&oid, kind, body);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(invalid("git batch output ends inside a header"));
    }
    Ok(complete)
}
