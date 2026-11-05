//! Core half of `merge_queue::file_metadata`: its store-layer items live in `oneiron_store::merge_queue::file_metadata` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::merge_queue::file_metadata::*;

use super::MergeFile;
use crate::error::{Error, Result};
use crate::git_wire::bundle_tree::{
    BundleTreeEdit, gitlink_index_entries, stage_bundle_tree_edits,
};
use crate::store::code_document_values::CodeFileMetadataEdit;
use crate::store::code_tree_blob::MODE_GITLINK;
use crate::store::contract_oracle::{invalid, safe_entry_path};
use std::path::Path;

/// Applies a received bundle's `files` to the speculative tree `root`: each
/// path must hold exactly its expected state (bytes, or their BLAKE3 for a
/// withheld base, FIX 10974) and mode, read without following a link,
/// before any entry changes.
///
/// # Errors
/// A stale or overlapping base, or a Git failure.
pub(super) fn materialize_received_merge_files(root: &Path, files: &[MergeFile]) -> Result<()> {
    let gitlinks = gitlink_index_entries(root)?;
    let mut edits = Vec::with_capacity(files.len());
    for file in files {
        let edit = file
            .metadata_edit
            .as_ref()
            .ok_or_else(|| invalid("a received bundle file carries its state change"))?;
        if gitlinks.keys().any(|parent| {
            file.path
                .strip_prefix(parent.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        }) {
            return Err(invalid("a bundle cannot enter a linked repository"));
        }
        // Parents never follow a link; gitlinks name only their index OID.
        let path = safe_entry_path(root, &file.path)?;
        let (bytes, mode) = match gitlinks.get(&file.path) {
            Some(oid) => (Some(oid.clone()), Some(MODE_GITLINK)),
            None => entry_state(&path)?,
        };
        if !file.expects(bytes.as_deref()) || mode != edit.expected.mode {
            return Err(Error::ConcurrentWrite(
                "proposal bytes overlap or base is stale",
            ));
        }
        edits.push(BundleTreeEdit {
            path: file.path.clone(),
            content: file.content.clone(),
            mode: edit.replacement.mode.unwrap_or(0),
        });
    }
    edits.sort_by(|left, right| {
        (left.content.is_some(), &left.path).cmp(&(right.content.is_some(), &right.path))
    });
    stage_bundle_tree_edits(root, &edits, true)
}
