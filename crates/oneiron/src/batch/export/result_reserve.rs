//! The body instances an archive import's run results spill into (KS-2A,
//! FIX 5683 part A): minted before the import's one write transaction
//! opens, since no body instance is minted inside a writer. Each released
//! result occurrence the import will stage gets one (FIX 6648). Its archived
//! length and what custody knows now do not decide this: the writer's
//! secret scan can make a masked copy longer than the inline bound. One left
//! unspilled is debris, which the one retention policy removes.

use std::io::{Read, Seek};

use super::archive_index::{IndexedArchive, Tag};
use super::{ArchiveFiles, ArchiveRecordKind, ExportRun};
use crate::Vault;
use crate::error::Result;
use crate::store::result_manifest::StagedSinks;

/// What the import's run results sink through inside its writer: one
/// instance for each released occurrence the writer stages (FIX 6648). A
/// second occurrence of the same bytes gets its own. The values a sweep
/// replaces are read in the writer (KS-3).
pub(super) fn staged_result_sinks<R: Read + Seek>(
    vault: &Vault,
    archive: &IndexedArchive<'_, R>,
) -> Result<StagedSinks> {
    let mut count = 0usize;
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        for output in &run.outputs {
            let Some(blake3) = &output.blake3 else {
                continue;
            };
            if archive.files.file_len(blake3).is_some()
                && archive.index.contains(Tag::Released, blake3.as_bytes())?
            {
                count = count.saturating_add(1);
            }
        }
    }
    vault.staged_result_sinks(count)
}
