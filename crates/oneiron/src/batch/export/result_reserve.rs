//! The body instances an archive import's run results spill into (KS-2A,
//! FIX 5683 part A): minted before the import's one write transaction
//! opens, since no body instance is minted inside a writer. Each result
//! occurrence the import will stage that may spill gets one: past the
//! inline bound, or any one when the sweep may lengthen it. One left
//! unspilled is debris.

use std::io::{Read, Seek};

use super::archive_index::{IndexedArchive, Tag};
use super::{ArchiveFiles, ArchiveRecordKind, ExportRun};
use crate::Vault;
use crate::code_run::StagedSinks;
use crate::error::Result;

/// What the import's run results sink through inside its writer: the
/// values custody knows, read now, and an instance for each occurrence
/// that may spill.
pub(super) fn staged_result_sinks<R: Read + Seek>(
    vault: &Vault,
    archive: &IndexedArchive<'_, R>,
) -> Result<StagedSinks> {
    let sweeps = vault.known_values()?.is_some();
    let bound = vault.code_result_inline_bytes();
    let mut count = 0usize;
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        for output in &run.outputs {
            let Some(blake3) = &output.blake3 else {
                continue;
            };
            let Some(listed) = archive.files.file_len(blake3) else {
                continue;
            };
            if archive.index.contains(Tag::Released, blake3.as_bytes())?
                && (sweeps || listed > bound)
            {
                count = count.saturating_add(1);
            }
        }
    }
    vault.staged_result_sinks(count)
}
