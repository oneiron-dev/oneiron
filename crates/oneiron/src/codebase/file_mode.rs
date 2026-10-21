//! The Git file modes a code snapshot keeps (FIX 6869, G4 PR1).
//!
//! An import records each path's exact Git mode; an ordinary new file is
//! the one default below. A missing mode is never recovered from that
//! default: the snapshot codec requires it on every entry.
use crate::error::{CodeError, Error, Result};

/// The mode of an ordinary new file: a regular, non-executable blob.
pub const DEFAULT_CODE_FILE_MODE: u32 = 0o100_644;

/// An executable regular file.
const MODE_EXECUTABLE: u32 = 0o100_755;
/// A symbolic link, whose bytes are its target text.
const MODE_SYMLINK: u32 = 0o120_000;

/// Whether `mode` is one a code snapshot keeps: a regular file, an
/// executable or a symbolic link. A submodule link is no snapshot file.
///
/// # Errors
/// Any other mode.
pub(crate) fn validate_code_file_mode(mode: u32) -> Result<()> {
    if matches!(
        mode,
        DEFAULT_CODE_FILE_MODE | MODE_EXECUTABLE | MODE_SYMLINK
    ) {
        return Ok(());
    }
    Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
        "file mode must be 100644, 100755 or 120000",
    )))
}
