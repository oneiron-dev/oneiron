//! The removal archive files the receiver deletes (FIX 11797): one whose
//! import has committed, and one whose term passed with no import. Each
//! delete is logged by the archive's key alone, and one that fails never
//! touches an import.

use std::path::Path;

/// Deletes `path`, the file of the archive `receipt` at delivery `version`
/// whose import has committed (FIX 11797): the vault keeps the copy now, and
/// its readers answer it there until its term. A delete that fails is
/// logged by the archive's key alone and leaves the import as it stands;
/// the next start's sweep deletes it ([`super::import_dir`]).
pub(super) fn remove_imported(path: &Path, receipt: &str, version: u64) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            receipt = %receipt,
            version,
            kind = ?error.kind(),
            "imported removal archive file not deleted"
        ),
    }
}

/// Deletes `path`, the file of the archive `receipt` at delivery `version`
/// whose term, the version plus
/// [`oneiron::federation::REMOVAL_EXPORT_RETAIN_SECS`], has passed with no
/// import (FIX 11797): no import takes it in now. Logged by the archive's
/// key alone; a delete that fails is logged so and tried again at the next
/// start.
pub(super) fn remove_lapsed(path: &Path, receipt: &str, version: u64) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(
            receipt = %receipt,
            version,
            "removal archive file past its term, never imported, deleted"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            receipt = %receipt,
            version,
            kind = ?error.kind(),
            "removal archive file past its term not deleted"
        ),
    }
}
