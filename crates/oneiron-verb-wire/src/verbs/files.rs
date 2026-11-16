//! Moved from `crates/oneiron/src/verbs/files.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::files::metadata::FileReadiness;
use crate::note::files::source::FileHandle;
use crate::note::folder_source::original::FileOriginal;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
    /// key files); a list, even an empty one, replaces it. The `oneiron
    /// files attach` command's `--exclude` adds to the default list instead,
    /// and its `--no-default-exclude` drops the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
    /// The note kind a file lands as when its frontmatter names none;
    /// `observation` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// Converts an attached notes source to Files on the server's host.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceConvertRequest {
    /// The attached folder, as this host names it; the host canonicalizes it.
    pub path: String,
    /// Absent keeps the Files default exclusions. A list, even an empty
    /// one, replaces them, as on `vault.files.sources.attach`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
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
    /// Files the write door refused and folders that would not open (FIX
    /// 10246); a later rescan tries them again.
    pub failed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
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

/// `vault.files.sources.exclude`'s input: the source's new filters.
/// Absent leaves today's list; a list, even an empty one, replaces it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceExcludeRequest {
    pub source: EntityId,
    /// Only files whose path under the folder matches one. None is every
    /// file the source reads today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    /// What the host never opens. Absent keeps today's list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<String>>,
}

/// `vault.files.sources.exclude`'s answer: the source's filters as they
/// stand now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceExcludeAnswer {
    pub source: EntityId,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
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
    /// The path to continue after: the `next_cursor` of the previous page.
    /// Absent starts at the first file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many files to answer, at most [`MAX_FILES_PAGE_LIMIT`];
    /// [`DEFAULT_FILES_PAGE_LIMIT`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
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
    /// The kept original's blob artifact, exact version and content hash;
    /// absent when this ledger row names no kept original.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<FileOriginal>,
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

/// `vault.files.sources.files`'s answer: one page of the files the
/// source's ledger holds, in path order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesSourceFiles {
    pub source: EntityId,
    pub files: Vec<FilesFileView>,
    /// The last path on this page: pass it back as `cursor` for the next
    /// page. Absent when the ledger is exhausted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
