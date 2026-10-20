//! The small blobs a set of tips reaches through its whole history, read in
//! bounded batches: what a caller looking for Git-LFS pointers needs, past
//! the tip trees and across every ref it names.

use std::collections::HashSet;

use super::argv::FrozenGitArgv;
use super::failure::invalid;
use super::{GitOid, GitWire, GitWireRepo, GitWireResult};
use crate::error::Result;

/// Oids one `cat-file --batch-check` child sizes. Its answer, under a
/// hundred bytes an object, stays far inside the default output bound.
const SIZE_BATCH_OIDS: usize = 65_536;

/// Blob bytes one `cat-file --batch` child reads; the next blob goes to the
/// next child.
const READ_BATCH_BYTES: u64 = 4 * 1024 * 1024;

impl GitWire<'_> {
    /// Hands `visit` the bytes of each distinct blob smaller than
    /// `below_bytes` that `tips` reach, through every commit, tree and tag of
    /// their history, in the order git walks them. `Ok(false)` when the walk
    /// met an object this store does not hold, so part of the graph went
    /// unread; every blob it could read is still visited.
    pub fn for_each_reachable_blob_below(
        &self,
        repo: &GitWireRepo,
        tips: &[GitOid],
        below_bytes: u64,
        mut visit: impl FnMut(&GitOid, &[u8]),
    ) -> GitWireResult<bool> {
        let mut distinct = HashSet::new();
        let tips: Vec<GitOid> = tips
            .iter()
            .filter(|oid| distinct.insert(*oid))
            .cloned()
            .collect();
        if tips.is_empty() {
            return Ok(true);
        }
        let argv = FrozenGitArgv::reachable_objects_below(&tips, below_bytes);
        let listing = self.run_read(repo, &argv)?;
        let mut complete = true;
        let mut reached = Vec::new();
        for line in listing.stdout.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.first() == Some(&b'?') {
                complete = false;
                continue;
            }
            let text = std::str::from_utf8(line)
                .map_err(|_| invalid("git object listing must be UTF-8"))?;
            reached.push(GitOid::parse_hex(text)?);
        }
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
                    complete &= self.read_blob_batch(repo, &batch, &mut visit)?;
                    batch.clear();
                    batch_bytes = 0;
                }
                batch_bytes = batch_bytes.saturating_add(size);
                batch.push(oid);
            }
        }
        if !batch.is_empty() {
            complete &= self.read_blob_batch(repo, &batch, &mut visit)?;
        }
        Ok(complete)
    }

    /// Reads one batch of blobs into `visit`; `Ok(false)` when one was gone.
    fn read_blob_batch(
        &self,
        repo: &GitWireRepo,
        oids: &[GitOid],
        visit: &mut impl FnMut(&GitOid, &[u8]),
    ) -> Result<bool> {
        let output = self.run_read(repo, &FrozenGitArgv::read_objects(oids))?;
        parse_batch_objects(&output.stdout, visit)
    }
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

/// Walks `cat-file --batch` output, handing each blob's bytes to `visit`.
/// `Ok(false)` when an object was missing.
fn parse_batch_objects(mut rest: &[u8], visit: &mut impl FnMut(&GitOid, &[u8])) -> Result<bool> {
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
        if kind == "blob" {
            visit(&oid, body);
        }
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(invalid("git batch output ends inside a header"));
    }
    Ok(complete)
}
