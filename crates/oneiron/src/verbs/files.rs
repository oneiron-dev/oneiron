//! The inputs and answers of the Files world's source rows (FIX 6942):
//! `vault.files.sources.attach`, `.rescan`, `.detach`, `.list` and `.files`,
//! host doors. A server runs each under the vault owner's proof. Attach and
//! rescan read folders on the server's own host, so an embedded handle,
//! which has no host walk, answers them with a typed refusal; its owner may
//! list, read a source's ledger and detach.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::note::{
    FileHandle, FileReadiness, FolderFileState, FolderRescanReport, FolderSource, FolderSourceFile,
};

/// `vault.files.sources.attach`'s input: the folder, and what of it the
/// source reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceAttachRequest {
    /// The folder, as the host names it; the host keeps its canonical path.
    pub path: String,
    /// Only files whose path under the folder matches one (`*` within a
    /// name, `**` across folders, `?` one character). None is every file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    /// What the host never opens, matched against each entry's name and its
    /// path under the folder. Absent keeps the default list (hidden entries,
    /// version control, dependency and build folders, credential stores and
    /// key files); a list, even an empty one, replaces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// The note kind a file lands as when its frontmatter names none;
    /// `observation` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// This install's Files world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesWorldView {
    pub world: EntityId,
    /// The install whose files it holds.
    pub machine: EntityId,
}

/// One Files source as the owner reviews it, with its ledger's counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceView {
    /// The source's id: its install, world and folder.
    pub source: EntityId,
    pub folder: String,
    pub world: EntityId,
    pub machine: EntityId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub kind: String,
    /// Recording time of the attach (Unix seconds).
    pub attached_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rescan_at: Option<u64>,
    /// Files the ledger holds, parts of a long file each counted.
    pub files: u64,
    /// Held by their name only.
    pub name_only: u64,
    /// Left the folder; their notes are archived.
    pub retracted: u64,
    /// Changed after the owner edited their note: forks wait for review.
    pub proposed: u64,
}

/// What one rescan of a Files source did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesRescanCounts {
    pub landed: u64,
    pub links: u64,
    pub unchanged: u64,
    pub superseded: u64,
    pub proposed: u64,
    pub retracted: u64,
    pub restored: u64,
    pub removed: u64,
    pub name_only: u64,
    /// Files the write door refused; a later rescan tries them again.
    pub failed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
}

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

/// An `[limits]` row a source's read crossed: it was read whole all the
/// same, and the row asks whether everything is okay (OF-520).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesLimitCrossed {
    pub row: String,
    pub limit: u64,
    pub observed: u64,
}

/// Files a rescan imported whose original could not be kept or named on
/// their ledger rows (FIX 7779): their text landed all the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesOriginalsUnkept {
    pub files: u64,
    pub first_error: String,
}

/// One rescan of a Files source: its counts, or why it read nothing (a
/// folder that is not there now retracts nothing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesRescanView {
    pub source: EntityId,
    pub folder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<FilesRescanCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits_crossed: Vec<FilesLimitCrossed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub originals_unkept: Option<FilesOriginalsUnkept>,
}

/// `vault.files.sources.attach`'s answer: the world (born on the first
/// attach), the source and its first rescan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceAttachAnswer {
    pub world: FilesWorldView,
    pub source: FilesSourceView,
    pub rescan: FilesRescanView,
}

/// `vault.files.sources.rescan`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceRescanRequest {
    /// The source; every Files source when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<EntityId>,
}

/// `vault.files.sources.rescan`'s answer, one rescan per source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesRescanAnswer {
    pub rescans: Vec<FilesRescanView>,
}

/// `vault.files.sources.detach`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceDetachRequest {
    pub source: EntityId,
}

/// `vault.files.sources.detach`'s answer. The notes the source landed stay;
/// no rescan reads the folder again and its ledger goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceDetachAnswer {
    pub source: EntityId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// False when no Files source has that id; nothing changed.
    pub detached: bool,
}

/// `vault.files.sources.list`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceListRequest {}

/// `vault.files.sources.list`'s answer: the world, once the owner opted in,
/// and every Files source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<FilesWorldView>,
    pub sources: Vec<FilesSourceView>,
}

/// `vault.files.sources.files`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceFilesRequest {
    pub source: EntityId,
}

/// Where one file of a Files source stands in its ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilesFileState {
    /// Its note holds the file's text, or the owner's edits of it.
    Landed,
    /// Changed after the owner edited its note: a fork waits for review.
    Proposed,
    /// Left the folder; its note is archived.
    Retracted,
    /// Held by its name only.
    NameOnly,
}

/// One file of a Files source, as its ledger holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesFileView {
    pub handle: FileHandle,
    pub state: FilesFileState,
    pub readiness: FileReadiness,
    /// The note its text landed as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<EntityId>,
    /// The fork its changed text waits as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork: Option<EntityId>,
    /// The revision the vault took: the hash of a PDF's bytes, else of the
    /// file's text; none for a file held by name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// When the file was last written (Unix seconds), at that revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen_at: Option<u64>,
    /// When the vault last took its text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed_at: Option<u64>,
}

/// `vault.files.sources.files`'s answer: every file the source's ledger
/// holds, in path order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceFiles {
    pub source: EntityId,
    pub files: Vec<FilesFileView>,
}

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
fn files_file_view(source: EntityId, file: FolderSourceFile) -> FilesFileView {
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
        bytes: meta.map(|meta| meta.bytes),
        modified_at: meta.map(|meta| meta.modified_at),
        first_seen_at: meta.map(|meta| meta.first_seen_at),
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

/// `vault.files.sources.files` under the owner's proof.
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
    let files = vault
        .folder_source_files(&source.folder)?
        .into_iter()
        .map(|file| files_file_view(input.source, file))
        .collect();
    Ok(FilesSourceFiles {
        source: input.source,
        files,
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
