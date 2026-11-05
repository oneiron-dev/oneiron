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

use crate::git_wire::failure::GitWireFailure;
use crate::git_wire::failure::GitWireFailureClass;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::objects::GitTreeEntry;
use crate::git_wire::objects::parse_tree_entries;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// Oids one `cat-file --batch-check` child sizes. Its answer, under a
/// hundred bytes an object, stays far inside the default output bound.
pub const SIZE_BATCH_OIDS: usize = 65_536;

/// Blob bytes one `cat-file --batch` child reads; the next blob goes to the
/// next child.
pub const READ_BATCH_BYTES: u64 = 4 * 1024 * 1024;

/// Commits one topological page lists with their parents, about eighty
/// bytes a commit. A page whose listing overflows is asked again at half.
pub const COMMIT_PAGE: usize = 65_536;

/// Commits whose objects one reachable-objects call lists. A call that
/// overflows or runs out of time splits in half.
pub const OBJECT_SLICE_COMMITS: usize = 2_048;

/// Direct entries of one tree the walk takes at a time, the oids one size
/// batch carries.
pub const TREE_PAGE_ENTRIES: usize = SIZE_BATCH_OIDS;

/// The tree entry mode of a tree.
pub const TREE_MODE: u32 = 0o040_000;

/// The tree entry mode of a submodule's commit, which this store does not
/// hold.
pub const GITLINK_MODE: u32 = 0o160_000;

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
pub type PagedCommit = (GitOid, Vec<GitOid>);

/// Whether a failed call passed its output or runtime bound, so a smaller
/// call may finish.
pub fn past_bound(failure: &GitWireFailure) -> bool {
    matches!(
        failure.class(),
        GitWireFailureClass::OutputOverflow | GitWireFailureClass::Timeout
    )
}

/// A `rev-list --objects --no-object-names --missing=print` listing: the
/// oids it reached, and whether it met no missing object.
pub fn parse_listing(stdout: &[u8]) -> Result<(Vec<GitOid>, bool)> {
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
pub fn parse_commit_page(stdout: &[u8]) -> Result<Vec<PagedCommit>> {
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
pub fn parse_peeled(stdout: &[u8]) -> Result<Vec<Option<(GitOid, String)>>> {
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
pub fn parse_object_sizes(stdout: &[u8]) -> Result<Vec<(GitOid, Option<(String, u64)>)>> {
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
pub fn parse_batch_objects(
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
