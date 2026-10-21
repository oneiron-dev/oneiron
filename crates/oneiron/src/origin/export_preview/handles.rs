//! A preview's identity and its byte handles (FIX 6869, G4 PR3, CALL O).
//!
//! The identity is recomputed from the pins and both complete pinned trees
//! on every call: no table, cache, token, key or expiry. It binds the
//! served name, the anchor, the origin and object store, the revision, the
//! full ref, the explicit expectation and both roots, then the sealed
//! revision's partition digest and the all-blob digest of each captured
//! side. No time, live ref, endpoint, checkout or caller enters it, so a
//! ref that moves rebinds nothing. A handle is an unsigned selector into
//! the changed paths of that recomputed preview.
use std::collections::BTreeMap;

use super::PinnedLeaf;
use super::types::{CodeExportByteHandle, CodeExportFileBytes, CodeExportPreview, CodeExportSide};
use crate::EntityId;
use crate::code_revision::{CodeTreeBlob, CodeTreeInventory};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

/// The one versioned identity domain (CALL O `preview_identity`).
const PREVIEW_IDENTITY_DOMAIN: &[u8] = b"oneiron:code-export-preview:v1";

/// The pins and both complete trees one preview's identity binds.
pub(super) struct PreviewIdentity<'a> {
    pub(super) served: &'a str,
    pub(super) code_repo: EntityId,
    pub(super) origin_repo_id: EntityId,
    pub(super) object_store: &'a str,
    pub(super) revision: EntityId,
    pub(super) ref_name: &'a str,
    pub(super) expected_old_oid: Option<&'a str>,
    pub(super) source_tree: Option<&'a str>,
    pub(super) target_tree: &'a str,
    pub(super) inventory_digest: &'a [u8; 32],
    pub(super) before: &'a BTreeMap<String, CodeTreeBlob>,
    pub(super) after: &'a BTreeMap<String, CodeTreeBlob>,
}

impl PreviewIdentity<'_> {
    /// The preview digest, 64 lower-hex: each part length-prefixed, each
    /// optional part tagged, then the digests in their fixed order.
    pub(super) fn digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREVIEW_IDENTITY_DOMAIN);
        part(&mut hasher, self.served.as_bytes());
        part(&mut hasher, self.code_repo.as_bytes());
        part(&mut hasher, self.origin_repo_id.as_bytes());
        part(&mut hasher, self.object_store.as_bytes());
        part(&mut hasher, self.revision.as_bytes());
        part(&mut hasher, self.ref_name.as_bytes());
        optional(&mut hasher, self.expected_old_oid);
        optional(&mut hasher, self.source_tree);
        part(&mut hasher, self.target_tree.as_bytes());
        hasher.update(self.inventory_digest);
        hasher.update(&CodeTreeInventory::blob_digest(self.before));
        hasher.update(&CodeTreeInventory::blob_digest(self.after));
        bytes_to_hex_lower(hasher.finalize().as_bytes())
    }
}

fn part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn optional(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(value) => {
            hasher.update(&[1]);
            part(hasher, value.as_bytes());
        }
    }
}

/// The one leaf `handle` selects in `preview`'s changed paths, its bytes
/// verified against its identity again. `Ok(Err(_))` names an invalid
/// selector: another digest, an unchanged path or an absent side. No
/// host file, object id or live tree stands in.
///
/// # Errors
/// A pinned leaf missing or differing from its identity: corruption.
pub(super) fn select_leaf(
    preview: &CodeExportPreview,
    before: &BTreeMap<String, PinnedLeaf>,
    after: &BTreeMap<String, PinnedLeaf>,
    handle: &CodeExportByteHandle,
) -> Result<std::result::Result<CodeExportFileBytes, &'static str>> {
    if handle.preview_digest != preview.preview_digest {
        return Ok(Err(
            "the handle names another preview than this request's recomputed one",
        ));
    }
    let Ok(at) = preview
        .files
        .binary_search_by(|delta| delta.path.as_str().cmp(handle.path.as_str()))
    else {
        return Ok(Err(
            "the handle's path is not a changed path of this preview",
        ));
    };
    let delta = &preview.files[at];
    let (identity, leaves) = match handle.side {
        CodeExportSide::Before => (&delta.before, before),
        CodeExportSide::After => (&delta.after, after),
    };
    let Some(identity) = identity else {
        return Ok(Err("the handle's side holds no file at this path"));
    };
    let leaf = leaves.get(&handle.path).ok_or(Error::InvariantViolation(
        "a changed preview leaf is missing from its pinned tree",
    ))?;
    if leaf.bytes.len() as u64 != identity.size_bytes
        || leaf.blob.mode != identity.mode
        || leaf.blob.git_oid != identity.git_oid
        || bytes_to_hex_lower(blake3::hash(&leaf.bytes).as_bytes()) != identity.content_hash
    {
        return Err(Error::InvariantViolation(
            "a pinned preview leaf differs from its identity",
        ));
    }
    Ok(Ok(CodeExportFileBytes {
        handle: handle.clone(),
        mode: identity.mode,
        size_bytes: identity.size_bytes,
        git_oid: identity.git_oid.clone(),
        content_hash: identity.content_hash.clone(),
        bytes: leaf.bytes.clone(),
    }))
}
