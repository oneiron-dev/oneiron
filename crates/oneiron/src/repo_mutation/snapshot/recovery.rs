//! Recovery bytes and custody use the same held checkout entries as capture.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use crate::error::{CodeError, Error, Result};

use super::capture::{CaptureEntry, Directory, visit_capture_entries};
use super::{
    MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES, MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES, SnapshotCustody,
    SnapshotStats, StoredRepoSnapshotEntry, is_executable, record_snapshot_entry_size,
};

pub(super) fn collect_snapshot_entries(
    repo_root: &Path,
    custody: &SnapshotCustody,
    indexed_paths: &BTreeSet<String>,
    linked_paths: &BTreeSet<String>,
    entries: &mut Vec<StoredRepoSnapshotEntry>,
    stats: &mut SnapshotStats,
) -> Result<()> {
    let directory = Directory::open_root(repo_root)?;
    visit_capture_entries(
        &directory,
        indexed_paths,
        linked_paths,
        &mut |relative, entry| {
            match entry {
                CaptureEntry::File(mut file) => {
                    let metadata = file.metadata()?;
                    if metadata.len() > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                            "repo mutation snapshot file exceeds max bytes",
                        )));
                    }
                    let remaining =
                        MAX_REPO_MUTATION_SNAPSHOT_TOTAL_BYTES.saturating_sub(stats.total_bytes);
                    let limit = MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES.min(remaining);
                    let mut content = Vec::with_capacity(metadata.len().min(limit) as usize);
                    (&mut file).take(limit + 1).read_to_end(&mut content)?;
                    if content.len() as u64 > MAX_REPO_MUTATION_SNAPSHOT_FILE_BYTES {
                        return Err(Error::Code(CodeError::InvalidRepoMutationRecord(
                            "repo mutation snapshot file exceeds max bytes",
                        )));
                    }
                    record_snapshot_entry_size(stats, content.len() as u64)?;
                    entries.push(custody.file(relative, is_executable(&metadata), content));
                }
                link @ CaptureEntry::Symlink { expected, .. } => {
                    let target = read_symlink(&link, expected)?;
                    record_snapshot_entry_size(stats, target.len() as u64)?;
                    entries.push(custody.symlink(relative, target));
                }
            }
            Ok(())
        },
    )
    .map_err(|error| match error {
        Error::Code(CodeError::InvalidCodebaseSnapshotBody(_)) => {
            Error::Code(CodeError::InvalidRepoMutationRecord(
                "repo snapshot supports only files, directories, and symlinks",
            ))
        }
        other => other,
    })
}

fn read_symlink(entry: &CaptureEntry<'_>, expected: u64) -> Result<String> {
    let initial = usize::try_from(expected)
        .map_err(|_| Error::ArithmeticOverflow("repo snapshot symlink length"))?
        .max(1);
    let mut bytes = vec![0; initial];
    loop {
        let read = entry.read_link(&mut bytes)?;
        if read < bytes.len() {
            bytes.truncate(read);
            return String::from_utf8(bytes).map_err(|_| {
                Error::Code(CodeError::InvalidRepoMutationRecord("path must be UTF-8"))
            });
        }
        let next = bytes
            .len()
            .checked_mul(2)
            .ok_or(Error::ArithmeticOverflow("repo snapshot symlink length"))?;
        bytes.resize(next, 0);
    }
}
