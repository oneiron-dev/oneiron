//! A masked copy's objects and its store (FIX 7608 slice 2b-i, CALL P2
//! `PreservePayload`).
//!
//! A copy keeps every object it does not have to change byte for byte, so
//! the copy store holds it at its original OID. An object changes only
//! because something it names changed: a blob a mark covers, then each
//! tree, commit and tag above it. The structural encoders change exactly
//! the object ids such an object names and nothing else: a tree keeps each
//! entry's mode bytes, name bytes and order; a commit keeps its parent
//! order and every other header and its message as stored; a tag keeps its
//! headers and message. A changed commit or tag can no longer carry the
//! signature it was made with, so its signature headers (`gpgsig`,
//! `gpgsig-sha256`, `mergetag`) and a tag's signature trailer are dropped
//! and the payload says `signature_not_preserved`: nothing is ever
//! re-signed.
//!
//! The copy store is a fresh bare store made through the one process
//! constructor with no template, hook, alternate, commondir or shared
//! object directory. Objects enter it one by one through the ordinary
//! object effect, never by hard link, clone or replace ref, and with no
//! keep-ref each (FIX 9106): the copy's root refs pin its whole closure
//! once they are published, and nothing maintains a copy store before.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

use std::collections::HashMap;
use std::path::Path;

use crate::code_snapshot::repo_ref::RepoRef;
use crate::git_wire::config::GIT_WIRE_MAX_PUBLICATIONS;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefPublication;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::record::GitWireCommitOutcome;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use crate::git_wire::repo::repo_identity_for;
use crate::git_wire::retained_object::GitObjectKind;
use crate::git_wire::retained_object::GitRetainedObject;
use crate::git_wire::retained_object::GitSpool;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

/// The bare store's directory inside a copy's own directory.
pub const PROJECTION_STORE_REPO: &str = "repo.git";

/// The headers a changed commit or tag drops: each signs bytes that no
/// longer exist.
const SIGNATURE_HEADERS: [&[u8]; 3] = [b"gpgsig", b"gpgsig-sha256", b"mergetag"];

/// The header keys naming the ids a commit's copy rewrites.
const COMMIT_ID_KEYS: [&[u8]; 2] = [b"tree ", b"parent "];

/// The header key naming the id a tag's copy rewrites.
const TAG_ID_KEYS: [&[u8]; 1] = [b"object "];

/// The lines a tag's signature trailer starts with.
const SIGNATURE_TRAILERS: [&[u8]; 3] = [
    b"-----BEGIN PGP SIGNATURE-----",
    b"-----BEGIN SSH SIGNATURE-----",
    b"-----BEGIN SIGNED MESSAGE-----",
];

/// Raw bytes of one SHA-1 object id inside a tree object.
pub const RAW_OID_BYTES: usize = 20;

/// The tree entry mode of a submodule commit: it names an object of
/// another repository, which no copy follows or rewrites.
pub const GITLINK_MODE: u32 = 0o160_000;

/// One object of a masked copy as it is written into the copy store: the
/// original's own bytes when nothing it names changed, else its structural
/// re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProjectedPayload {
    pub object: GitRetainedObject,
    pub changed: bool,
    pub signature_not_preserved: bool,
}

impl GitProjectedPayload {
    /// The object to write.
    pub const fn object(&self) -> &GitRetainedObject {
        &self.object
    }

    /// Whether the payload differs from the original's bytes.
    pub const fn changed(&self) -> bool {
        self.changed
    }

    /// Whether a signature the original carried was dropped.
    pub const fn signature_not_preserved(&self) -> bool {
        self.signature_not_preserved
    }
}

/// One place an object names another inside its own repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitObjectEdge {
    /// A tree entry, with its stored mode and name bytes.
    TreeEntry {
        mode: u32,
        name: Vec<u8>,
        oid: GitOid,
    },
    /// A commit's tree.
    CommitTree(GitOid),
    /// A commit's parent at this position.
    CommitParent { index: u32, oid: GitOid },
    /// A tag's target.
    TagTarget(GitOid),
}

impl GitObjectEdge {
    /// The object named.
    pub const fn target(&self) -> &GitOid {
        match self {
            Self::TreeEntry { oid, .. }
            | Self::CommitTree(oid)
            | Self::CommitParent { oid, .. }
            | Self::TagTarget(oid) => oid,
        }
    }
}

/// Every object `object` names inside its own repository, in its stored
/// order: a tree's entries (but a submodule's commit, which lives in
/// another repository), a commit's tree then parents, a tag's target. A
/// blob names none.
///
/// # Errors
/// A malformed object.
pub fn git_object_edges(object: &GitRetainedObject) -> GitWireResult<Vec<GitObjectEdge>> {
    let raw = object.read_bytes()?;
    match object.kind() {
        GitObjectKind::Blob => Ok(Vec::new()),
        GitObjectKind::Tree => Ok(tree_entries(&raw)?
            .into_iter()
            .filter(|entry| entry.mode != GITLINK_MODE)
            .map(|entry| GitObjectEdge::TreeEntry {
                mode: entry.mode,
                name: entry.name,
                oid: entry.oid,
            })
            .collect()),
        GitObjectKind::Commit => {
            let (headers, _) = split_headers(&raw)?;
            let mut edges = Vec::new();
            let mut index: u32 = 0;
            for line in header_lines(headers) {
                if let Some(oid) = header_oid(line, b"tree ")? {
                    edges.push(GitObjectEdge::CommitTree(oid));
                } else if let Some(oid) = header_oid(line, b"parent ")? {
                    edges.push(GitObjectEdge::CommitParent { index, oid });
                    index = index.saturating_add(1);
                }
            }
            Ok(edges)
        }
        GitObjectKind::Tag => {
            let (headers, _) = split_headers(&raw)?;
            for line in header_lines(headers) {
                if let Some(oid) = header_oid(line, b"object ")? {
                    return Ok(vec![GitObjectEdge::TagTarget(oid)]);
                }
            }
            Err(invalid("git tag object names no target"))
        }
    }
}

pub fn unchanged(original: &GitRetainedObject) -> GitProjectedPayload {
    GitProjectedPayload {
        object: original.clone(),
        changed: false,
        signature_not_preserved: false,
    }
}

/// One entry of a raw tree object, with where its object id's bytes sit.
pub struct RawTreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub oid: GitOid,
    pub oid_at: usize,
}

/// A raw tree object's entries: `<octal mode> <name>\0<20 id bytes>` each.
pub fn tree_entries(raw: &[u8]) -> Result<Vec<RawTreeEntry>> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        let space = raw[at..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| invalid("a git tree entry has no mode separator"))?;
        let mode = std::str::from_utf8(&raw[at..at + space])
            .ok()
            .and_then(|mode| u32::from_str_radix(mode, 8).ok())
            .ok_or_else(|| invalid("a git tree entry mode is not octal"))?;
        let name_at = at + space + 1;
        let nul = raw[name_at..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("a git tree entry name is not terminated"))?;
        let oid_at = name_at + nul + 1;
        let oid_end = oid_at + RAW_OID_BYTES;
        let oid_bytes = raw
            .get(oid_at..oid_end)
            .ok_or_else(|| invalid("a git tree entry's object id is cut short"))?;
        entries.push(RawTreeEntry {
            mode,
            name: raw[name_at..name_at + nul].to_vec(),
            oid: GitOid::parse_hex(bytes_to_hex_lower(oid_bytes))?,
            oid_at,
        });
        at = oid_end;
    }
    Ok(entries)
}

/// The 20 raw bytes of a SHA-1 object id.
pub fn raw_oid(oid: &GitOid) -> Result<[u8; RAW_OID_BYTES]> {
    let hex = oid.as_str().as_bytes();
    let mut out = [0_u8; RAW_OID_BYTES];
    if hex.len() != RAW_OID_BYTES * 2 {
        return Err(invalid("a copy's object id is not a SHA-1 id"));
    }
    for (index, pair) in hex.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| invalid("an object id is not hex"))?;
        out[index] =
            u8::from_str_radix(text, 16).map_err(|_| invalid("an object id is not hex"))?;
    }
    Ok(out)
}

/// `raw` with each entry's id replaced by its copy's; `None` when no entry
/// names a changed id. Modes, names and order stay as stored.
pub fn encode_tree(raw: &[u8], copies: &HashMap<GitOid, GitOid>) -> Result<Option<Vec<u8>>> {
    let mut out: Option<Vec<u8>> = None;
    for entry in tree_entries(raw)? {
        if entry.mode == GITLINK_MODE {
            continue;
        }
        let Some(copy) = copies.get(&entry.oid) else {
            continue;
        };
        let bytes = out.get_or_insert_with(|| raw.to_vec());
        bytes[entry.oid_at..entry.oid_at + RAW_OID_BYTES].copy_from_slice(&raw_oid(copy)?);
    }
    Ok(out)
}

/// A commit's or tag's header block and its message, split at the first
/// blank line.
fn split_headers(raw: &[u8]) -> Result<(&[u8], &[u8])> {
    if raw.starts_with(b"\n") {
        return Ok((&raw[..0], &raw[1..]));
    }
    match raw.windows(2).position(|pair| pair == b"\n\n") {
        Some(at) => Ok((&raw[..=at], &raw[at + 2..])),
        None if raw.ends_with(b"\n") => Ok((raw, &raw[raw.len()..])),
        None => Err(invalid("a git object's headers are not terminated")),
    }
}

/// Each header line with its continuation lines, newline included.
fn header_lines(headers: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut at = 0;
    while at < headers.len() {
        let mut end = at;
        loop {
            match headers[end..].iter().position(|byte| *byte == b'\n') {
                Some(nl) => end += nl + 1,
                None => end = headers.len(),
            }
            if end >= headers.len() || headers[end] != b' ' {
                break;
            }
        }
        lines.push(&headers[at..end]);
        at = end;
    }
    lines
}

/// The object id a `<key><hex>\n` header line names, when it is that key.
fn header_oid(line: &[u8], key: &[u8]) -> Result<Option<GitOid>> {
    let Some(rest) = line.strip_prefix(key) else {
        return Ok(None);
    };
    let hex = rest.strip_suffix(b"\n").unwrap_or(rest);
    let hex = std::str::from_utf8(hex).map_err(|_| invalid("a git header object id is not hex"))?;
    GitOid::parse_hex(hex).map(Some)
}

/// The header line's key: the bytes before its first space.
fn header_key(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(line.len());
    &line[..end]
}

/// A commit (or, with `tag`, a tag) with each `tree`, `parent` or `object`
/// id replaced by its copy's; `None` when it names no changed id. A changed
/// one drops its signature headers, and a changed tag its signature
/// trailer; the flag says whether any was there.
pub fn encode_headed(
    raw: &[u8],
    copies: &HashMap<GitOid, GitOid>,
    tag: bool,
) -> Result<Option<(Vec<u8>, bool)>> {
    let (headers, message) = split_headers(raw)?;
    let keys: &[&[u8]] = if tag { &TAG_ID_KEYS } else { &COMMIT_ID_KEYS };
    let mut changed = false;
    for line in header_lines(headers) {
        for key in keys {
            if let Some(oid) = header_oid(line, key)?
                && copies.contains_key(&oid)
            {
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut dropped = false;
    for line in header_lines(headers) {
        let key = header_key(line);
        if SIGNATURE_HEADERS.iter().any(|signature| *signature == key) {
            dropped = true;
            continue;
        }
        let mut replaced = false;
        for key in keys {
            if let Some(oid) = header_oid(line, key)? {
                let next = copies.get(&oid).unwrap_or(&oid);
                out.extend_from_slice(key);
                out.extend_from_slice(next.as_str().as_bytes());
                out.push(b'\n');
                replaced = true;
            }
        }
        if !replaced {
            out.extend_from_slice(line);
        }
    }
    out.push(b'\n');
    let message = if tag {
        match signature_trailer_at(message) {
            Some(at) => {
                dropped = true;
                &message[..at]
            }
            None => message,
        }
    } else {
        message
    };
    out.extend_from_slice(message);
    Ok(Some((out, dropped)))
}

/// Where a tag message's signature trailer starts: the first line that
/// opens one.
fn signature_trailer_at(message: &[u8]) -> Option<usize> {
    let mut at = 0;
    while at < message.len() {
        if SIGNATURE_TRAILERS
            .iter()
            .any(|trailer| message[at..].starts_with(trailer))
        {
            return Some(at);
        }
        at += message[at..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(message.len() - at, |nl| nl + 1);
    }
    None
}

/// A tag object's target, the target's type and the tag's name bytes, from
/// its headers.
///
/// # Errors
/// A tag with no `object` or `type`, or of an unknown type.
pub fn tag_header(raw: &[u8]) -> Result<(GitOid, GitObjectKind, Vec<u8>)> {
    let (headers, _) = split_headers(raw)?;
    let (mut target, mut kind, mut name) = (None, None, Vec::new());
    for line in header_lines(headers) {
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        if let Some(oid) = header_oid(line, b"object ")? {
            target = Some(oid);
        } else if let Some(value) = body.strip_prefix(b"type ") {
            let value =
                std::str::from_utf8(value).map_err(|_| invalid("a git tag type is not text"))?;
            kind = Some(GitObjectKind::parse(value)?);
        } else if let Some(value) = body.strip_prefix(b"tag ") {
            name = value.to_vec();
        }
    }
    match (target, kind) {
        (Some(target), Some(kind)) => Ok((target, kind, name)),
        _ => Err(invalid("git tag object names no target")),
    }
}
