//! The inputs and answers of the Files world's source rows (FIX 6942):
//! `vault.files.sources.attach`, `.convert`, `.rescan`, `.detach`, `.list`, `.files`
//! and `.exclude` host doors. A server runs each under the vault owner's proof.
//! Attach, conversion and rescan read folders on the server's host, so an embedded handle,
//! which has no host walk, answers them with a typed refusal; its owner may
//! list, read a source's ledger and detach.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::note::{
    FileHandle, FileReadiness, FolderFileState, FolderRescanReport, FolderSource, FolderSourceFile,
};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::files::{
    FilesFileState, FilesFileView, FilesLimitCrossed, FilesOriginalsUnkept, FilesRescanAnswer,
    FilesRescanCounts, FilesRescanView, FilesSourceAttachAnswer, FilesSourceAttachRequest,
    FilesSourceConvertRequest, FilesSourceDetachAnswer, FilesSourceDetachRequest,
    FilesSourceExcludeAnswer, FilesSourceExcludeRequest, FilesSourceFiles, FilesSourceFilesRequest,
    FilesSourceList, FilesSourceListRequest, FilesSourceRescanRequest, FilesSourceView,
    FilesWorldView,
};

impl From<FolderRescanReport> for FilesRescanCounts {
    fn from(report: FolderRescanReport) -> Self {
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        Self {
            landed: count(report.landed),
            links: count(report.links),
            unchanged: count(report.unchanged),
            superseded: count(report.superseded),
            proposed: count(report.proposed),
            retracted: count(report.retracted),
            restored: count(report.restored),
            removed: count(report.removed),
            name_only: count(report.name_only),
            failed: count(report.failed),
            first_error: report.first_error,
        }
    }
}

/// How many files `vault.files.sources.files` answers when its input names
/// no limit (FIX 10247).
pub const DEFAULT_FILES_PAGE_LIMIT: u64 = 200;

/// How many files one `vault.files.sources.files` answer holds at most
/// (FIX 10247).
pub const MAX_FILES_PAGE_LIMIT: u64 = 1000;

/// The refusal an embedded handle answers a row that reads the host's
/// folders with: it has no host walk.
fn host_walk_only<T>(verb: &str) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} reads folders on a server's own host; an embedded vault reads none"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

/// The Files source `source` names.
fn files_source_named(vault: &Vault, source: EntityId) -> MemoryResult<FolderSource> {
    vault.files_source(source)?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no Files source has that id",
            &["List the Files sources: vault.files.sources.list."],
        )
    })
}

/// `source` as the owner reviews it, its ledger counted.
///
/// # Errors
/// A source that is not a Files source, or a storage error.
pub fn files_source_view(vault: &Vault, source: &FolderSource) -> MemoryResult<FilesSourceView> {
    let files = source.files.as_ref().ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the folder is attached as notes, not to the Files world",
            &[],
        )
    })?;
    let ledger = vault.folder_source_files(&source.folder)?;
    let count = |wanted: fn(&FolderFileState) -> bool| {
        u64::try_from(ledger.iter().filter(|file| wanted(&file.state)).count()).unwrap_or(u64::MAX)
    };
    Ok(FilesSourceView {
        source: files.source,
        folder: source.folder.clone(),
        world: files.world,
        machine: files.machine,
        include: source.include.clone(),
        exclude: files.exclude.clone(),
        kind: source.kind.clone(),
        attached_at: source.attached_at,
        last_rescan_at: source.last_rescan_at,
        files: u64::try_from(ledger.len()).unwrap_or(u64::MAX),
        name_only: count(|state| matches!(state, FolderFileState::NameOnly { .. })),
        retracted: count(|state| *state == FolderFileState::Retracted),
        proposed: count(|state| matches!(state, FolderFileState::Proposed { .. })),
    })
}

/// One ledger row as `vault.files.sources.files` answers it.
pub(super) fn files_file_view(source: EntityId, file: FolderSourceFile) -> FilesFileView {
    let readiness = file.readiness();
    let (state, fork) = match file.state {
        FolderFileState::Landed => (FilesFileState::Landed, None),
        FolderFileState::Proposed { fork } => (FilesFileState::Proposed, fork),
        FolderFileState::Retracted => (FilesFileState::Retracted, None),
        FolderFileState::NameOnly { .. } => (FilesFileState::NameOnly, None),
    };
    let revision = match readiness {
        FileReadiness::Text => file
            .raw_hash
            .or_else(|| (!file.file_hash.is_empty()).then_some(file.file_hash)),
        FileReadiness::NameOnly { .. } => None,
    };
    let meta = file.meta;
    // The row keeps when it first saw the file; ledgers written before it
    // still carry it on the meta (REVIEW-4381 P1).
    let first_seen_at = match file.first_seen_at {
        0 => meta.map(|meta| meta.first_seen_at),
        seen => Some(seen),
    };
    FilesFileView {
        handle: FileHandle {
            source,
            path: file.path,
        },
        state,
        readiness,
        note: file.note,
        fork,
        revision,
        original: file.original,
        bytes: meta.map(|meta| meta.bytes),
        modified_at: meta.map(|meta| meta.modified_at),
        first_seen_at,
        indexed_at: meta.and_then(|meta| meta.indexed_at),
    }
}

/// `vault.files.sources.list` under the owner's proof.
///
/// # Errors
/// A proof that no longer holds, or a storage error.
pub fn list_files_sources_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: FilesSourceListRequest,
) -> MemoryResult<FilesSourceList> {
    owner.revalidate(vault)?;
    let world = vault.files_world()?.map(|files| FilesWorldView {
        world: files.world,
        machine: files.machine,
    });
    let sources = vault
        .files_sources()?
        .iter()
        .map(|source| files_source_view(vault, source))
        .collect::<MemoryResult<Vec<_>>>()?;
    Ok(FilesSourceList { world, sources })
}

/// `vault.files.sources.files` under the owner's proof: one page of the
/// ledger in path order (FIX 10247).
///
/// # Errors
/// A proof that no longer holds, no Files source of that id, or a storage
/// error.
pub fn files_source_files_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FilesSourceFilesRequest,
) -> MemoryResult<FilesSourceFiles> {
    owner.revalidate(vault)?;
    let source = files_source_named(vault, input.source)?;
    let take = usize::try_from(input.limit.unwrap_or(DEFAULT_FILES_PAGE_LIMIT))
        .unwrap_or(usize::MAX)
        .clamp(
            1,
            usize::try_from(MAX_FILES_PAGE_LIMIT).unwrap_or(usize::MAX),
        );
    let mut ledger = vault.folder_source_files(&source.folder)?;
    // Ledger keys hash overlong paths, so path order is sorted here, not
    // read off the keys.
    ledger.sort_by(|left, right| left.path.cmp(&right.path));
    let start = input.cursor.as_ref().map_or(0, |cursor| {
        ledger.partition_point(|file| file.path <= *cursor)
    });
    let mut page: Vec<FilesFileView> = ledger
        .into_iter()
        .skip(start)
        .take(take.saturating_add(1))
        .map(|file| files_file_view(input.source, file))
        .collect();
    let next_cursor = if page.len() > take {
        page.pop();
        page.last().map(|file| file.handle.path.clone())
    } else {
        None
    };
    Ok(FilesSourceFiles {
        source: input.source,
        files: page,
        next_cursor,
    })
}

/// `vault.files.sources.exclude` under the owner's proof: the source reads
/// with its new filters from its next rescan (FIX 10248).
///
/// # Errors
/// A proof that no longer holds, no Files source of that id, a folder
/// attached as notes, or a storage error.
pub fn exclude_files_source_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FilesSourceExcludeRequest,
) -> MemoryResult<FilesSourceExcludeAnswer> {
    owner.revalidate(vault)?;
    let source =
        vault.set_folder_source_filters(owner, input.source, input.include, input.exclude)?;
    let exclude = source.files.map(|files| files.exclude).unwrap_or_default();
    Ok(FilesSourceExcludeAnswer {
        source: input.source,
        include: source.include,
        exclude,
    })
}

/// `vault.files.sources.detach` under the owner's proof: the source's
/// ledger goes and its notes stay.
///
/// # Errors
/// A proof that no longer holds, or a storage error.
pub fn detach_files_source_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: FilesSourceDetachRequest,
) -> MemoryResult<FilesSourceDetachAnswer> {
    owner.revalidate(vault)?;
    let Some(source) = vault.files_source(input.source)? else {
        return Ok(FilesSourceDetachAnswer {
            source: input.source,
            folder: None,
            detached: false,
        });
    };
    let detached = vault.detach_folder_source(owner, &source.folder)?;
    Ok(FilesSourceDetachAnswer {
        source: input.source,
        folder: Some(source.folder),
        detached,
    })
}

/// `vault.files.sources.attach` on an embedded handle: it has no host walk.
pub fn attach_files_source_embedded(
    _memory: &Memory<'_>,
    _input: FilesSourceAttachRequest,
) -> MemoryResult<FilesSourceAttachAnswer> {
    host_walk_only("vault.files.sources.attach")
}

/// `vault.files.sources.convert` on an embedded handle: it has no host walk.
pub fn convert_files_source_embedded(
    _memory: &Memory<'_>,
    _input: FilesSourceConvertRequest,
) -> MemoryResult<FilesSourceAttachAnswer> {
    host_walk_only("vault.files.sources.convert")
}

/// `vault.files.sources.rescan` on an embedded handle: it has no host walk.
pub fn rescan_files_sources_embedded(
    _memory: &Memory<'_>,
    _input: FilesSourceRescanRequest,
) -> MemoryResult<FilesRescanAnswer> {
    host_walk_only("vault.files.sources.rescan")
}

/// `vault.files.sources.detach` on an embedded handle: the embedded owner's
/// own act.
pub fn detach_files_source_embedded(
    memory: &Memory<'_>,
    input: FilesSourceDetachRequest,
) -> MemoryResult<FilesSourceDetachAnswer> {
    let owner = memory.embedded_owner("vault.files.sources.detach")?;
    detach_files_source_as(memory.vault(), &owner, input)
}

/// `vault.files.sources.list` on an embedded handle: the embedded owner's
/// own read.
pub fn list_files_sources_embedded(
    memory: &Memory<'_>,
    input: FilesSourceListRequest,
) -> MemoryResult<FilesSourceList> {
    let owner = memory.embedded_owner("vault.files.sources.list")?;
    list_files_sources_as(memory.vault(), &owner, input)
}

/// `vault.files.sources.files` on an embedded handle: the embedded owner's
/// own read.
pub fn files_source_files_embedded(
    memory: &Memory<'_>,
    input: FilesSourceFilesRequest,
) -> MemoryResult<FilesSourceFiles> {
    let owner = memory.embedded_owner("vault.files.sources.files")?;
    files_source_files_as(memory.vault(), &owner, input)
}

/// `vault.files.sources.exclude` on an embedded handle: the embedded owner's
/// own act.
pub fn exclude_files_source_embedded(
    memory: &Memory<'_>,
    input: FilesSourceExcludeRequest,
) -> MemoryResult<FilesSourceExcludeAnswer> {
    let owner = memory.embedded_owner("vault.files.sources.exclude")?;
    exclude_files_source_as(memory.vault(), &owner, input)
}
