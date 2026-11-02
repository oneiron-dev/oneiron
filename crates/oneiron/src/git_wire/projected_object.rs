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
//! object writer, never by hard link, clone or replace ref.

#![allow(
    dead_code,
    reason = "FIX 7608 slice 2b-i: preparation only; slice 2b-ii is the first caller"
)]

use std::collections::HashMap;
use std::path::Path;

use super::config::GIT_WIRE_MAX_PUBLICATIONS;
use super::failure::{classify_failure, invalid};
use super::import_fetch::init_private_bare_store;
use super::repo::repo_identity_for;
use super::retained_object::{GitObjectKind, GitRetainedObject, GitSpool};
use super::{
    GitOid, GitRefPublication, GitWire, GitWireCommitOutcome, GitWireOperation, GitWireRepo,
    GitWireResult,
};
use crate::codebase::RepoRef;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;

/// The bare store's directory inside a copy's own directory.
const PROJECTION_STORE_REPO: &str = "repo.git";

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
const RAW_OID_BYTES: usize = 20;

/// The tree entry mode of a submodule commit: it names an object of
/// another repository, which no copy follows or rewrites.
const GITLINK_MODE: u32 = 0o160_000;

/// One object of a masked copy as it is written into the copy store: the
/// original's own bytes when nothing it names changed, else its structural
/// re-encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProjectedPayload {
    object: GitRetainedObject,
    changed: bool,
    signature_not_preserved: bool,
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
pub(crate) enum GitObjectEdge {
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
    pub(crate) const fn target(&self) -> &GitOid {
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
pub(crate) fn git_object_edges(object: &GitRetainedObject) -> GitWireResult<Vec<GitObjectEdge>> {
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

impl GitWire<'_> {
    /// A blob of a masked copy: the original when `copy` is `None` or holds
    /// the original's own bytes, else `copy` sealed in a fresh spool.
    ///
    /// # Errors
    /// An IO failure.
    pub fn project_blob(
        &self,
        original: &GitRetainedObject,
        copy: Option<&[u8]>,
    ) -> GitWireResult<GitProjectedPayload> {
        let Some(copy) = copy else {
            return Ok(unchanged(original));
        };
        if *blake3::hash(copy).as_bytes() == original.content_blake3() {
            return Ok(unchanged(original));
        }
        let spool = GitSpool::pump(self.spool_dir(), copy)?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(GitObjectKind::Blob, spool),
            changed: true,
            signature_not_preserved: false,
        })
    }

    /// A tree, commit or tag of a masked copy: each object id it names
    /// replaced by its copy's in `copies` (which holds only ids that
    /// changed), and nothing else changed. With no named id in `copies`
    /// the payload is the original's own bytes.
    ///
    /// # Errors
    /// A malformed object, a blob, or an IO failure.
    pub fn project_structural(
        &self,
        original: &GitRetainedObject,
        copies: &HashMap<GitOid, GitOid>,
    ) -> GitWireResult<GitProjectedPayload> {
        let raw = original.read_bytes()?;
        let encoded = match original.kind() {
            GitObjectKind::Blob => {
                return Err(invalid("a blob has no structure to re-encode"));
            }
            GitObjectKind::Tree => encode_tree(&raw, copies)?.map(|bytes| (bytes, false)),
            GitObjectKind::Commit => encode_headed(&raw, copies, false)?,
            GitObjectKind::Tag => encode_headed(&raw, copies, true)?,
        };
        let Some((bytes, signature_dropped)) = encoded else {
            return Ok(unchanged(original));
        };
        let spool = GitSpool::pump(self.spool_dir(), bytes.as_slice())?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(original.kind(), spool),
            changed: true,
            signature_not_preserved: signature_dropped,
        })
    }

    /// A tree of a recipient copy (FIX 7608 pre-flip, FIX 9328): each entry
    /// `copies` names by its name bytes pointed at that copy, at the very
    /// id position it is stored at, and nothing else changed. One id named
    /// by two entries may so take two copies; a submodule's entry is never
    /// rewritten. With no entry rewritten the payload is the original's.
    ///
    /// # Errors
    /// A malformed tree, an object that is not a tree, or an IO failure.
    pub(crate) fn project_tree_occurrences(
        &self,
        original: &GitRetainedObject,
        copies: &HashMap<Vec<u8>, GitOid>,
    ) -> GitWireResult<GitProjectedPayload> {
        if !matches!(original.kind(), GitObjectKind::Tree) {
            return Err(invalid("only a tree is re-encoded by occurrence"));
        }
        let raw = original.read_bytes()?;
        let mut out: Option<Vec<u8>> = None;
        for entry in tree_entries(&raw)? {
            if entry.mode == GITLINK_MODE {
                continue;
            }
            let Some(copy) = copies.get(&entry.name).filter(|copy| **copy != entry.oid) else {
                continue;
            };
            let bytes = out.get_or_insert_with(|| raw.to_vec());
            bytes[entry.oid_at..entry.oid_at + RAW_OID_BYTES].copy_from_slice(&raw_oid(copy)?);
        }
        let Some(bytes) = out else {
            return Ok(unchanged(original));
        };
        let spool = GitSpool::pump(self.spool_dir(), bytes.as_slice())?;
        Ok(GitProjectedPayload {
            object: GitRetainedObject::encoded(GitObjectKind::Tree, spool),
            changed: true,
            signature_not_preserved: false,
        })
    }

    /// Makes the fresh bare store a masked copy is written into, at
    /// `root/repo.git`, and binds it for object writes and ref
    /// publications. `root` must not hold a store yet. The handle pins no
    /// commit: nothing in the store is proved until its graph is whole, and
    /// a reader opens it with `open_repo` on the copy's root afterwards.
    ///
    /// # Errors
    /// A store that cannot be made, or one that is not its own common
    /// directory or shares objects with another.
    pub(crate) fn init_projection_store(&self, root: &Path) -> GitWireResult<GitWireRepo> {
        std::fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        if root.join(PROJECTION_STORE_REPO).exists() {
            return Err(invalid("a masked copy's store already exists"));
        }
        let output = init_private_bare_store(&self.process_env, &root, PROJECTION_STORE_REPO)?;
        if !output.success {
            return Err(classify_failure(&output).error(GitWireOperation::ImportScratchInit));
        }
        let repo_root = root.join(PROJECTION_STORE_REPO).canonicalize()?;
        self.bind_projection_store(&repo_root)
    }

    /// Publishes a fresh copy store's refs, each batch the publication
    /// bound holds through the one transactional path (whole-graph
    /// availability proved for each target). The store serves nothing until
    /// its records stand, so the batches need not be one transaction, and
    /// no count bound ends the set.
    ///
    /// # Errors
    /// A failed or refused publication.
    pub(crate) fn publish_projection_refs(
        &self,
        copy_store: &GitWireRepo,
        publications: Vec<GitRefPublication>,
        now: u64,
    ) -> GitWireResult<()> {
        for batch in publications.chunks(GIT_WIRE_MAX_PUBLICATIONS) {
            match self.publish_refs(copy_store, batch.to_vec(), now)? {
                GitWireCommitOutcome::Applied(_) | GitWireCommitOutcome::Replayed(_) => {}
                GitWireCommitOutcome::Rejected { .. } => {
                    return Err(invalid("a masked copy's fresh store refused its refs"));
                }
            }
        }
        Ok(())
    }

    /// The bare copy store at `root/repo.git`, bound for writes, or `None`
    /// when there is none.
    ///
    /// # Errors
    /// A store that is not its own common directory or shares objects.
    pub(crate) fn existing_projection_store(
        &self,
        root: &Path,
    ) -> GitWireResult<Option<GitWireRepo>> {
        let candidate = root.join(PROJECTION_STORE_REPO);
        if !candidate.exists() {
            return Ok(None);
        }
        self.bind_projection_store(&candidate.canonicalize()?)
            .map(Some)
    }

    fn bind_projection_store(&self, repo_root: &Path) -> Result<GitWireRepo> {
        let common_dir = self.canonical_common_dir(repo_root)?;
        if common_dir != repo_root {
            return Err(invalid(
                "a masked copy's store must be its own common directory",
            ));
        }
        for shared in [
            "commondir",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            if common_dir.join(shared).exists() {
                return Err(invalid("a masked copy's store must not share objects"));
            }
        }
        Ok(GitWireRepo {
            repo_ref: RepoRef::LocalFolder {
                path: repo_root.to_string_lossy().into_owned(),
                commit: String::new(),
            },
            repo_root: repo_root.to_path_buf(),
            identity: repo_identity_for(&common_dir),
            common_dir,
        })
    }
}

fn unchanged(original: &GitRetainedObject) -> GitProjectedPayload {
    GitProjectedPayload {
        object: original.clone(),
        changed: false,
        signature_not_preserved: false,
    }
}

/// One entry of a raw tree object, with where its object id's bytes sit.
struct RawTreeEntry {
    mode: u32,
    name: Vec<u8>,
    oid: GitOid,
    oid_at: usize,
}

/// A raw tree object's entries: `<octal mode> <name>\0<20 id bytes>` each.
fn tree_entries(raw: &[u8]) -> Result<Vec<RawTreeEntry>> {
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
fn raw_oid(oid: &GitOid) -> Result<[u8; RAW_OID_BYTES]> {
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
fn encode_tree(raw: &[u8], copies: &HashMap<GitOid, GitOid>) -> Result<Option<Vec<u8>>> {
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
fn encode_headed(
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
pub(super) fn tag_header(raw: &[u8]) -> Result<(GitOid, GitObjectKind, Vec<u8>)> {
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
