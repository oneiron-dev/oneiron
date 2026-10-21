//! A received bundle's files in speculation (FIX 6869, G4 PR2): each one's
//! reviewed exact Git state change, checked against the speculative tree
//! without following a link, then applied through the index, removals
//! first. The whole bundle is one proposal and one mask bit; an ordinary
//! file (no state change) stages exactly as before.
use std::path::Path;

use super::MergeFile;
use crate::code_document::CodeFileMetadataEdit;
use crate::contract_oracle::{invalid, safe_path};
use crate::error::{Error, Result};
use crate::repo_mutation::{ReceivedTreeEdit, stage_received_tree_edits};

/// A symlink's Git mode.
const MODE_SYMLINK: u32 = 0o120_000;

/// One received file's reviewed state change as the queue admits it:
/// well-formed presence on both sides, bytes exactly when present, no
/// rename, and a real change of bytes or state. Deletion and equal bytes
/// are admitted on this source-bound path alone.
///
/// # Errors
/// A malformed or empty change.
pub(super) fn validate_received_merge_file(
    file: &MergeFile,
    edit: &CodeFileMetadataEdit,
) -> Result<()> {
    if edit.path != file.path
        || edit.new_path.is_some()
        || edit.expected.validate().is_err()
        || edit.replacement.validate().is_err()
        || file.expected.is_some() != edit.expected.present
        || file.content.is_some() != edit.replacement.present
        || (file.expected == file.content && edit.expected == edit.replacement)
    {
        return Err(invalid("received merge file state change is invalid"));
    }
    Ok(())
}

/// Applies a received bundle's `files` to the speculative tree `root`: each
/// path must hold exactly its expected bytes and mode, read without
/// following a link, before any entry changes.
///
/// # Errors
/// A stale or overlapping base, or a Git failure.
pub(super) fn materialize_received_merge_files(root: &Path, files: &[MergeFile]) -> Result<()> {
    let mut edits = Vec::with_capacity(files.len());
    for file in files {
        let edit = file
            .metadata_edit
            .as_ref()
            .ok_or_else(|| invalid("a received bundle file carries its state change"))?;
        let (bytes, mode) = entry_state(&safe_path(root, &file.path)?)?;
        if bytes != file.expected || mode != edit.expected.mode {
            return Err(Error::ConcurrentWrite(
                "proposal bytes overlap or base is stale",
            ));
        }
        edits.push(ReceivedTreeEdit {
            path: file.path.clone(),
            content: file.content.clone(),
            mode: edit.replacement.mode.unwrap_or(0),
        });
    }
    edits.sort_by(|left, right| {
        (left.content.is_some(), &left.path).cmp(&(right.content.is_some(), &right.path))
    });
    stage_received_tree_edits(root, &edits, true)
}

/// The bytes and Git mode a path holds, without following a link: a
/// symlink's target text, a file's bytes, nothing for anything else.
fn entry_state(path: &Path) -> Result<(Option<Vec<u8>>, Option<u32>)> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((None, None)),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)?;
        let target = target
            .to_str()
            .ok_or_else(|| invalid("a symlink target must be UTF-8"))?;
        return Ok((Some(target.as_bytes().to_vec()), Some(MODE_SYMLINK)));
    }
    if !metadata.is_file() {
        return Ok((None, None));
    }
    Ok((Some(std::fs::read(path)?), Some(file_mode(&metadata))))
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        0o100_755
    } else {
        crate::codebase::DEFAULT_CODE_FILE_MODE
    }
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    crate::codebase::DEFAULT_CODE_FILE_MODE
}
