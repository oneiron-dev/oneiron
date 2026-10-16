//! A local folder that stays attached to the vault (OF-554, ARCH-0027).
//!
//! The owner attaches a folder of markdown notes once. Each rescan lands what
//! changed since the last one, under that standing act:
//! - a new file lands as the one-shot import lands it, as an owner-written
//!   NOTE with its title and links;
//! - a changed file supersedes the text it landed. When the note still holds
//!   that text, the file's text replaces it through the note edit door, so its
//!   history is kept. When the owner has edited the note since, the file's
//!   text lands as a fork for review instead, and the owner's edits stay;
//! - a file gone from the folder retracts its note. The note is archived, a
//!   local marker that keeps its body, and the rescan restores it when the
//!   file comes back. Never an erase.
//!
//! Files only feed the vault. Nothing is written back to the folder: the
//! vault is the base and files are never it (ENJ-029). A per-file ledger
//! remembers what each file last held and what the vault took from it.

use serde::{Deserialize, Serialize};

use super::documents::{NoteEdit, NoteEditOutcome};
use super::import::{
    ImportedNote, ImportedNoteBatch, ImportedNoteLink, NOTES_IMPORT_SOURCE, revision, scan_titles,
    validate_batch,
};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

const SOURCES: SideTable<String, FolderSource, Named> = SideTable::new(&side_table::FOLDER_SOURCE);
const FILES: SideTable<String, FolderSourceFile, Named> =
    SideTable::new(&side_table::FOLDER_SOURCE_FILE);

/// The longest path a ledger key holds as is; a longer one keys by its hash.
const MAX_KEYED_PATH: usize = 256;

/// The longest folder a source names.
const MAX_FOLDER_BYTES: usize = 4096;

/// The most include patterns one source keeps, and the longest of them.
const MAX_INCLUDES: usize = 64;
const MAX_INCLUDE_BYTES: usize = 512;

/// How long the edit door may diff a changed file against its note.
const WHOLE_TEXT_TIMEOUT_MS: u32 = 2_000;

/// An attached folder: what the owner attached, and when it was last read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSource {
    /// The folder, as the host names it (canonical).
    pub folder: String,
    /// Which files under it are notes: patterns over the `/`-separated path
    /// under the folder. Empty is every markdown file.
    pub include: Vec<String>,
    /// The note kind a file lands as when its frontmatter names none.
    pub kind: String,
    /// The registered ingest source the files enter under.
    pub source: String,
    /// That source's trust tier: what the vault takes the files to be.
    pub trust: ClaimSource,
    pub attached_by: EntityId,
    pub attached_at: u64,
    pub last_rescan_at: Option<u64>,
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
    /// The file left the folder; its note is archived.
    Retracted,
}

/// What the ledger knows of one file of an attached folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSourceFile {
    /// Under the folder, `/`-separated.
    pub path: String,
    pub note: EntityId,
    /// The hash of the file's text at the last rescan that took it.
    pub file_hash: String,
    /// The hash of the text the vault took from the file, when known.
    pub landed_hash: String,
    pub state: FolderFileState,
}

/// One file the folder holds, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderFile {
    pub path: String,
    pub markdown: String,
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
    /// Paths in the ledger that left the folder.
    pub missing: Vec<String>,
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
                attached_by,
                attached_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                last_rescan_at: None,
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

    /// One rescan of an attached folder: lands its new files, supersedes
    /// what its changed files landed and retracts what its missing files
    /// landed. A file the write door refuses is counted and tried again by
    /// the next rescan; the rest still land.
    ///
    /// # Errors
    /// A folder that is not attached, or a storage error.
    pub fn rescan_folder_source(
        &self,
        owner: &AuthenticatedOwner,
        rescan: FolderRescan,
    ) -> Result<FolderRescanReport> {
        let FolderRescan {
            folder,
            new,
            links,
            present,
            missing,
        } = rescan;
        let key = source_key(&folder);
        if self.folder_source(&folder)?.is_none() {
            return Err(super::document::invalid("the folder is not attached"));
        }
        let owner_actor = owner.revalidate(self)?;
        let mut report = FolderRescanReport::default();
        self.land_new_files(owner, &folder, new, links, &mut report)?;
        for file in &present {
            self.rescan_present_file(owner_actor, &folder, file, &mut report)?;
        }
        for path in &missing {
            self.retract_missing_file(&folder, path, &mut report)?;
        }
        self.with_write_txn(|txn| {
            if let Some(mut source) = SOURCES.get(&self.store, txn, &key)? {
                source.last_rescan_at = Some(crate::ports::recorded_at_in_txn(&self.store, txn)?);
                SOURCES.put(&self.store, txn, &key, &source)?;
            }
            Ok(())
        })?;
        Ok(report)
    }

    /// Lands the new files in one write. When the write door refuses one,
    /// each lands alone and the links follow, so one file keeps none of the
    /// rest out.
    fn land_new_files(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        notes: Vec<ImportedNote>,
        links: Vec<ImportedNoteLink>,
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        if notes.is_empty() {
            return Ok(());
        }
        let batch = ImportedNoteBatch {
            request_id: self.new_entity_id()?,
            folder: folder.to_owned(),
            notes,
            links,
        };
        match self.land_folder_batch(owner, &batch) {
            Ok(links) => {
                report.landed += batch.notes.len();
                report.links += links;
                return Ok(());
            }
            Err(error) => {
                report.first_error.get_or_insert_with(|| error.to_string());
            }
        }
        let mut left_out = std::collections::HashSet::new();
        for note in &batch.notes {
            let alone = ImportedNoteBatch {
                request_id: self.new_entity_id()?,
                folder: folder.to_owned(),
                notes: vec![note.clone()],
                links: Vec::new(),
            };
            match self.land_folder_batch(owner, &alone) {
                Ok(_) => report.landed += 1,
                Err(error) => {
                    report.fail(error);
                    left_out.insert(note.path.as_str());
                }
            }
        }
        let links = batch
            .links
            .iter()
            .filter(|link| {
                !left_out.contains(link.from.as_str()) && !left_out.contains(link.to.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        if !links.is_empty() {
            let landed = self.with_write_txn(|txn| {
                let owner_actor = owner.revalidate_in_txn(self, txn)?;
                self.land_imported_notes_in_txn(
                    txn,
                    owner_actor,
                    folder,
                    &[],
                    Vec::new(),
                    &[],
                    &links,
                )
            });
            match landed {
                Ok(links) => report.links += links,
                Err(error) => {
                    report.first_error.get_or_insert_with(|| error.to_string());
                }
            }
        }
        Ok(())
    }

    /// Lands `batch` and its ledger rows in one write.
    fn land_folder_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedNoteBatch,
    ) -> Result<usize> {
        validate_batch(batch)?;
        let kinds = batch
            .notes
            .iter()
            .map(|note| self.note_kind(&note.kind))
            .collect::<Result<Vec<_>>>()?;
        let ids = batch
            .notes
            .iter()
            .map(|note| Self::imported_note_id(&batch.folder, &note.path))
            .collect::<Result<Vec<_>>>()?;
        self.with_write_txn(|txn| {
            let owner_actor = owner.revalidate_in_txn(self, txn)?;
            scan_titles(&self.store, txn, batch)?;
            let links = self.land_imported_notes_in_txn(
                txn,
                owner_actor,
                &batch.folder,
                &batch.notes,
                kinds,
                &ids,
                &batch.links,
            )?;
            for (note, id) in batch.notes.iter().zip(&ids) {
                let hash = text_hash(&note.markdown);
                let row = FolderSourceFile {
                    path: note.path.clone(),
                    note: *id,
                    file_hash: hash.clone(),
                    landed_hash: hash,
                    state: FolderFileState::Landed,
                };
                FILES.put(&self.store, txn, &file_key(&batch.folder, &note.path), &row)?;
            }
            Ok(links)
        })
    }

    /// One file the folder still holds, against what its note holds.
    fn rescan_present_file(
        &self,
        owner_actor: EntityId,
        folder: &str,
        file: &FolderFile,
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        let key = file_key(folder, &file.path);
        let id = Self::imported_note_id(folder, &file.path)?;
        let hash = text_hash(&file.markdown);
        let (row, retracted) = {
            let txn = self.store.env.read_txn()?;
            let row = FILES.get(&self.store, &txn, &key)?;
            let retracted = row
                .as_ref()
                .is_some_and(|row| row.state == FolderFileState::Retracted);
            if !retracted && row.as_ref().is_some_and(|row| row.file_hash == hash) {
                report.unchanged += 1;
                return Ok(());
            }
            let raw = self.get_raw_in(&txn, &id)?;
            if raw.is_none() {
                // Never landed: the secret scan refused it when it was new.
                report.fail("the file's note never landed");
                return Ok(());
            }
            if crate::deletion::row_deletion_marked(&self.store, &txn, &id, raw.as_deref())? {
                report.removed += 1;
                return Ok(());
            }
            let archived = self.archive_tombstone_in_txn(&txn, &id)?.is_some();
            if archived && !retracted {
                report.removed += 1;
                return Ok(());
            }
            (row, archived)
        };
        if retracted {
            self.restore_archived(&id)?;
            report.restored += 1;
        }
        let current = self.note_text(id)?;
        let current_hash = text_hash(&current);
        let mut row = row.unwrap_or_else(|| FolderSourceFile {
            path: file.path.clone(),
            note: id,
            file_hash: String::new(),
            landed_hash: String::new(),
            state: FolderFileState::Landed,
        });
        if current == file.markdown {
            row.file_hash = hash.clone();
            row.landed_hash = hash;
            row.state = FolderFileState::Landed;
            if !retracted {
                report.unchanged += 1;
            }
            return self.with_write_txn(|txn| FILES.put(&self.store, txn, &key, &row));
        }
        // The note holds what the file gave it last (its first text, or a
        // later one the owner took from a fork): nothing of the owner's is
        // lost when the file's new text replaces it.
        let untouched = if row.landed_hash.is_empty() {
            let txn = self.store.env.read_txn()?;
            super::verbs::note_core(self, &txn, id)?
                .1
                .source_revision_ref
                == revision(folder, &file.path, &current)
        } else {
            current_hash == row.landed_hash || current_hash == row.file_hash
        };
        let edit = if untouched {
            NoteEdit::WholeText {
                text: file.markdown.clone(),
                timeout_ms: WHOLE_TEXT_TIMEOUT_MS,
                base: self.note_program_document(id)?.map(|doc| doc.version()),
            }
        } else {
            NoteEdit::Rewrite {
                text: file.markdown.clone(),
            }
        };
        let actor = WriteActor::new(owner_actor, EdgeActorClass::Human);
        row.state = match self.edit_note(id, &edit, actor) {
            Ok(NoteEditOutcome::Edited { .. }) => {
                report.superseded += 1;
                row.landed_hash = hash.clone();
                FolderFileState::Landed
            }
            Ok(NoteEditOutcome::RewriteFork { fork } | NoteEditOutcome::ProposedFork { fork }) => {
                report.proposed += 1;
                FolderFileState::Proposed { fork: Some(fork) }
            }
            Ok(NoteEditOutcome::ReviewRequired { .. }) => {
                report.proposed += 1;
                FolderFileState::Proposed { fork: None }
            }
            Err(error) => {
                report.fail(error);
                return Ok(());
            }
        };
        if untouched && row.landed_hash.is_empty() {
            row.landed_hash = current_hash;
        }
        row.file_hash = hash;
        self.with_write_txn(|txn| FILES.put(&self.store, txn, &key, &row))
    }

    /// A file gone from the folder: its note is archived, never erased.
    fn retract_missing_file(
        &self,
        folder: &str,
        path: &str,
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        let key = file_key(folder, path);
        let retracted = self.with_write_txn(|txn| {
            let Some(mut row) = FILES.get(&self.store, txn, &key)? else {
                return Ok(false);
            };
            if row.state == FolderFileState::Retracted {
                return Ok(false);
            }
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            self.archive_retracted_note_in_txn(txn, &row.note, at)?;
            row.state = FolderFileState::Retracted;
            FILES.put(&self.store, txn, &key, &row)?;
            Ok(true)
        })?;
        report.retracted += usize::from(retracted);
        Ok(())
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
