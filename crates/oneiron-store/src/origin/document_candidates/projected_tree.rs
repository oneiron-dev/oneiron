//! A projected candidate's canonical files and target tree (FIX 7608
//! slice 2b-ii-B2): the trees and bytes it reads, and the blobs and trees
//! its translation writes into the canonical store, from the ORIGINAL base
//! tree, each edited path set to its blob and mode or removed.

use std::collections::BTreeMap;

use crate::code_document_values::CodeFilePresence;
use crate::code_tree_blob::CodeTreeBlob;
use crate::git_wire::ids::GitOid;
use crate::git_wire::objects::GitTreeEntry;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::tree::OriginTreeFile;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// A tree's Git mode.
pub const MODE_TREE: u32 = 0o040_000;

pub fn presence(blob: Option<&CodeTreeBlob>) -> CodeFilePresence {
    blob.map_or_else(CodeFilePresence::absent, |blob| {
        CodeFilePresence::file(blob.mode)
    })
}

pub fn tree_blob(
    entries: &BTreeMap<String, (String, u32)>,
    files: &BTreeMap<String, OriginTreeFile>,
    path: &str,
) -> Option<CodeTreeBlob> {
    let (oid, mode) = entries.get(path)?;
    let content = files
        .get(path)
        .map_or(&[][..], |file| file.content.as_slice());
    Some(CodeTreeBlob {
        git_oid: oid.clone(),
        content_hash: *blake3::hash(content).as_bytes(),
        size_bytes: content.len() as u64,
        mode: *mode,
    })
}

/// One side of a changed file: its blob and its bytes, when present.
pub fn file_input<'f>(
    entries: &BTreeMap<String, (String, u32)>,
    files: &'f BTreeMap<String, OriginTreeFile>,
    path: &str,
) -> Result<Option<(GitOid, &'f [u8])>> {
    let Some((oid, _)) = entries.get(path) else {
        return Ok(None);
    };
    let bytes = files
        .get(path)
        .map_or(&[][..], |file| file.content.as_slice());
    Ok(Some((GitOid::parse_hex(oid.clone())?, bytes)))
}
