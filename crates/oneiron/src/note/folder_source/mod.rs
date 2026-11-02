//! A local folder that stays attached to the vault (OF-554, ARCH-0027).
//!
//! The owner attaches a folder of markdown notes and PDFs once. Each rescan
//! lands what changed since the last one, under that standing act:
//! - a new file lands as the one-shot import lands it, as an imported NOTE
//!   with its title and links. The folder's import MACHINE writes it, for the
//!   owner: the file's text is never taken for the owner's own writing;
//! - a changed file supersedes the text it landed. When the note still holds
//!   that text, the file's text replaces it through the note edit door, so its
//!   history is kept. The import MACHINE makes that edit too, so the owner's
//!   own edits stay the owner's. When the owner has edited the note since, the
//!   file's text lands as a fork for review instead, and the owner's edits stay;
//! - a file gone from the folder retracts its note. The note is archived, a
//!   local marker that keeps its body, and the rescan restores it when the
//!   file comes back. Never an erase.
//!
//! A folder attached to the Files world (FIX 6942, `note::files`) is the same
//! source with a placement: its notes are born in this install's Files
//! world, their ids derive from the source's identity rather than the host's
//! path, and a file with no text is held by its name only, never as text.
//!
//! Files only feed the vault. Nothing is written back to the folder: the
//! vault is the base and files are never it (ENJ-029). A per-file ledger
//! remembers what each file last held and what the vault took from it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::files::{
    FileFacts, FileMeta, FileReadiness, FilesPlacement, NameOnlyFile, NameOnlyReason,
};
use super::import::{ImportedNote, ImportedNoteLink, NOTES_IMPORT_SOURCE};
use super::proposals::{NoteActor, names_no_actor};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

mod original;
mod reconcile;

pub use original::{FileOriginal, OriginalBytes};

const SOURCES: SideTable<String, FolderSource, Named> = SideTable::new(&side_table::FOLDER_SOURCE);
const FILES: SideTable<String, FolderSourceFile, Named> =
    SideTable::new(&side_table::FOLDER_SOURCE_FILE);

/// Erasing `actor` from the folders it attached (FIX 3520): each attached
/// folder keeps its row, its ledger and its times, and names no one. One-way,
/// in the erase's own transaction. An id whose entity is no actor scans
/// nothing.
///
/// # Errors
///
/// Storage errors, or a source row that cannot be read.
pub(crate) fn erase_folder_source_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut sources = Vec::new();
    for (key, mut source) in SOURCES.scan(&vault.store, wtxn)? {
        if source.attached_by.is(*actor) {
            source.attached_by = NoteActor::Erased;
            sources.push((key, source));
        }
    }
    for (key, source) in sources {
        SOURCES.put(&vault.store, wtxn, &key, &source)?;
    }
    Ok(())
}

/// The longest path a ledger key holds as is; a longer one keys by its hash.
const MAX_KEYED_PATH: usize = 256;

/// The longest folder a source names.
const MAX_FOLDER_BYTES: usize = 4096;

/// The most include patterns one source keeps, and the longest of them.
const MAX_INCLUDES: usize = 64;
const MAX_INCLUDE_BYTES: usize = 512;

/// An attached folder: what the owner attached, and when it was last read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSource {
    /// The folder, as the host names it (canonical).
    pub folder: String,
    /// Which files under it are notes: patterns over the `/`-separated path
    /// under the folder. Empty is every file the source reads.
    pub include: Vec<String>,
    /// The note kind a file lands as when its frontmatter names none.
    pub kind: String,
    /// The registered ingest source the files enter under.
    pub source: String,
    /// That source's trust tier: what the vault takes the files to be.
    pub trust: ClaimSource,
    pub attached_by: NoteActor,
    pub attached_at: u64,
    pub last_rescan_at: Option<u64>,
    /// Where a Files source's files live (FIX 6942); none for a folder
    /// attached as notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<FilesPlacement>,
}

impl FolderSource {
    /// The name the source's notes, their import MACHINE and their revisions
    /// derive from: the folder itself for a folder attached as notes, the
    /// source's identity for a Files source, so no host path names them.
    #[must_use]
    pub fn namespace(&self) -> String {
        self.files.as_ref().map_or_else(
            || self.folder.clone(),
            |files| super::files::namespace(files.source),
        )
    }
}

/// Where one file of an attached folder stands in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderFileState {
    /// The note holds the file's text, or the owner's edits of it.
    Landed,
    /// The file changed after the owner edited its note: its text waits as a
    /// fork for review (none when the edit door asked for a review instead).
    Proposed { fork: Option<EntityId> },
    /// The file left the folder; its note, if it had one, is archived.
    Retracted,
    /// A Files source holds the file by its name only: it has no text the
    /// vault takes. A note its earlier text landed is archived until its
    /// text comes back.
    NameOnly { why: NameOnlyReason },
}

/// What the ledger knows of one file of an attached folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSourceFile {
    /// Under the folder, `/`-separated.
    pub path: String,
    /// The note the file's text landed as; none for a file the vault only
    /// ever held by its name.
    pub note: Option<EntityId>,
    /// The hash of the file's text at the last rescan that took it.
    pub file_hash: String,
    /// The hash of the text the vault took from the file, when known.
    pub landed_hash: String,
    /// The mentions targets this file's import landed (FIX 1363): the only
    /// edges a rescan deletes for it, never one another writer added.
    pub landed_links: Vec<EntityId>,
    /// The hash of the file's bytes, when its text was extracted from them
    /// (a PDF): its revision. A change to the bytes alone moves no text.
    pub raw_hash: Option<String>,
    pub state: FolderFileState,
    /// What a Files source knows of the file itself (FIX 6942); none for a
    /// folder attached as notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<FileMeta>,
    /// The kept original of the file's bytes as its last rescan read them
    /// (FIX 7779); a continuation part names its file's. None when no
    /// original was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<FileOriginal>,
}

impl FolderSourceFile {
    /// Whether the vault holds the file's text, or its name only.
    #[must_use]
    pub fn readiness(&self) -> FileReadiness {
        match self.state {
            FolderFileState::NameOnly { why } => FileReadiness::NameOnly { why },
            _ => FileReadiness::Text,
        }
    }
}

/// One file the folder holds, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderFile {
    pub path: String,
    pub markdown: String,
    /// The file's links as the host resolved them against the whole folder
    /// read, by path (FIX 1363); none when the read skipped files, so the
    /// rescan cannot tell a dropped link from an unread name.
    pub links: Option<Vec<String>>,
}

/// What the host read of an attached folder at one rescan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRescan {
    pub folder: String,
    /// Files no import landed yet, titles and kinds chosen, as
    /// [`Vault::imported_note_standings`] reads them `New`.
    pub new: Vec<ImportedNote>,
    /// The links the new notes bring.
    pub links: Vec<ImportedNoteLink>,
    /// Every other file the folder holds.
    pub present: Vec<FolderFile>,
    /// A Files source's files that have no text the vault takes.
    pub name_only: Vec<NameOnlyFile>,
    /// Paths in the ledger that left the folder.
    pub missing: Vec<String>,
    /// By path, the hash of the bytes of each file whose text was extracted
    /// from them (a PDF).
    pub raw_hashes: HashMap<String, String>,
    /// By path, what a Files source's host read of each file it holds as
    /// text; empty for a folder attached as notes.
    pub facts: HashMap<String, FileFacts>,
}

/// What one rescan did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FolderRescanReport {
    pub landed: usize,
    pub links: usize,
    pub unchanged: usize,
    /// Changed files whose text replaced their note's.
    pub superseded: usize,
    /// Changed files whose note the owner edited: forks for review.
    pub proposed: usize,
    pub retracted: usize,
    /// Notes a returning file brought back from the archive.
    pub restored: usize,
    /// Files whose note the owner deleted or archived: left as they are.
    pub removed: usize,
    /// Files a Files source now holds by name only, new or changed.
    pub name_only: usize,
    /// Files the write door refused; a later rescan tries them again.
    pub failed: usize,
    /// Why the first of them was refused.
    pub first_error: Option<String>,
}

impl FolderRescanReport {
    fn fail(&mut self, error: impl std::fmt::Display) {
        self.failed += 1;
        self.first_error.get_or_insert_with(|| error.to_string());
    }
}

impl Vault {
    /// Attaches `folder` as a standing source of notes. The owner's one act;
    /// each rescan after it lands under it.
    ///
    /// # Errors
    /// A blank or oversize folder or pattern, an unknown `kind`, an
    /// unregistered markdown source, a folder attached already, or a storage
    /// error.
    pub fn attach_folder_source(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        include: Vec<String>,
        kind: &str,
    ) -> Result<FolderSource> {
        self.attach_source(owner, folder, include, kind, None)
    }

    /// [`Self::attach_folder_source`], placed as `files` says when it is a
    /// Files source.
    pub(in crate::note) fn attach_source(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        include: Vec<String>,
        kind: &str,
        files: Option<FilesPlacement>,
    ) -> Result<FolderSource> {
        let invalid = super::document::invalid;
        if folder.trim().is_empty() || folder.len() > MAX_FOLDER_BYTES {
            return Err(invalid("a folder source names its folder"));
        }
        if include.len() > MAX_INCLUDES
            || include
                .iter()
                .any(|pattern| pattern.trim().is_empty() || pattern.len() > MAX_INCLUDE_BYTES)
        {
            return Err(invalid(
                "a folder source's include patterns are blank or too many",
            ));
        }
        self.note_kind(kind)?;
        let trust = crate::ingest::INGEST_SOURCE_REGISTRY
            .get_config(NOTES_IMPORT_SOURCE)
            .filter(|config| !config.writes_claims)
            .ok_or_else(|| invalid("the markdown import source is not registered"))?
            .trust_ceiling
            .claim_source;
        let key = source_key(folder);
        self.with_write_txn(|txn| {
            let attached_by = owner.revalidate_in_txn(self, txn)?;
            if SOURCES.contains(&self.store, txn, &key)? {
                return Err(invalid("the folder is attached already; detach it first"));
            }
            let source = FolderSource {
                folder: folder.to_owned(),
                include,
                kind: kind.to_owned(),
                source: NOTES_IMPORT_SOURCE.to_owned(),
                trust,
                attached_by: NoteActor::Actor(attached_by),
                attached_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                last_rescan_at: None,
                files,
            };
            SOURCES.put(&self.store, txn, &key, &source)?;
            Ok(source)
        })
    }

    /// Every attached folder.
    ///
    /// # Errors
    /// A storage error.
    pub fn folder_sources(&self) -> Result<Vec<FolderSource>> {
        let txn = self.store.env.read_txn()?;
        Ok(SOURCES
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, source)| source)
            .collect())
    }

    /// The attached `folder`, if it is attached.
    ///
    /// # Errors
    /// A storage error.
    pub fn folder_source(&self, folder: &str) -> Result<Option<FolderSource>> {
        let txn = self.store.env.read_txn()?;
        SOURCES.get(&self.store, &txn, &source_key(folder))
    }

    /// What the ledger knows of each file of `folder`.
    ///
    /// # Errors
    /// A storage error.
    pub fn folder_source_files(&self, folder: &str) -> Result<Vec<FolderSourceFile>> {
        let txn = self.store.env.read_txn()?;
        Ok(FILES
            .scan_from(&self.store, &txn, files_prefix(folder).as_bytes())?
            .into_iter()
            .map(|(_, file)| file)
            .collect())
    }

    /// Detaches `folder`: no rescan reads it again and its ledger goes. The
    /// notes it landed stay. `false` when it was not attached.
    ///
    /// # Errors
    /// A storage error.
    pub fn detach_folder_source(&self, owner: &AuthenticatedOwner, folder: &str) -> Result<bool> {
        let key = source_key(folder);
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            for file in FILES.scan_keys(&self.store, txn, files_prefix(folder).as_bytes())? {
                FILES.delete(&self.store, txn, &file)?;
            }
            SOURCES.delete(&self.store, txn, &key)
        })
    }
}

/// The ledger's name for `folder`.
fn source_key(folder: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron folder-source key v1");
    hasher.update(folder.as_bytes());
    hasher.finalize().to_hex()[..32].to_owned()
}

fn files_prefix(folder: &str) -> String {
    format!("{}:", source_key(folder))
}

fn file_key(folder: &str, path: &str) -> String {
    if path.len() <= MAX_KEYED_PATH {
        format!("{}{path}", files_prefix(folder))
    } else {
        format!(
            "{}#{}",
            files_prefix(folder),
            blake3::hash(path.as_bytes()).to_hex()
        )
    }
}

fn text_hash(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}
