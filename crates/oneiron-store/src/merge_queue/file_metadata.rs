//! A received bundle's files in speculation (FIX 6869, G4 PR2): each one's
//! reviewed exact Git state change, checked against the speculative tree
//! without following a link, then applied through the index, removals
//! first. The whole bundle is one proposal and one mask bit; an ordinary
//! file (no state change) stages exactly as before.
use std::path::Path;

use crate::code_document_values::CodeFileMetadataEdit;
use crate::code_tree_blob::MODE_GITLINK;
use crate::contract_oracle::invalid;
use crate::contract_oracle::safe_entry_path;
use crate::git_wire::bundle_tree::BundleTreeEdit;
use crate::merge_queue::types::MergeFile;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// A symlink's Git mode.
const MODE_SYMLINK: u32 = 0o120_000;

/// One received file's reviewed state change as the queue admits it:
/// well-formed presence on both sides, bytes exactly when present, no
/// rename, and a real change of bytes or state. Deletion and equal bytes
/// are admitted on this source-bound path alone.
///
/// # Errors
/// A malformed or empty change.
pub fn validate_received_merge_file(file: &MergeFile, edit: &CodeFileMetadataEdit) -> Result<()> {
    if edit.path != file.path
        || edit.new_path.is_some()
        || edit.expected.validate().is_err()
        || edit.replacement.validate().is_err()
        || file.expected.is_some() != edit.expected.present
        || file.content.is_some() != edit.replacement.present
        || (file.expects(file.content.as_deref()) && edit.expected == edit.replacement)
    {
        return Err(invalid("received merge file state change is invalid"));
    }
    Ok(())
}

/// The bytes and Git mode a path holds, without following a link: a
/// symlink's target text, a file's bytes, nothing for anything else.
pub fn entry_state(path: &Path) -> Result<(Option<Vec<u8>>, Option<u32>)> {
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
        crate::code_snapshot::file_mode::DEFAULT_CODE_FILE_MODE
    }
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    crate::code_snapshot::file_mode::DEFAULT_CODE_FILE_MODE
}
