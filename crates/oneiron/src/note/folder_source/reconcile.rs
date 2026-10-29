//! One rescan of an attached folder against its ledger: new files land,
//! changed files supersede what they landed, files with no text are held by
//! their name only, and missing files retract theirs.

use std::collections::{HashMap, HashSet};

use super::super::documents::{NoteProgramEdit, NoteProgramEditOutcome};
use super::super::files::{FileFacts, FileMeta, NameOnlyFile};
use super::super::import::{
    ImportedNote, ImportedNoteBatch, ImportedNoteLink, revision, scan_titles, validate_batch,
};
use super::{
    FILES, FolderFile, FolderFileState, FolderRescan, FolderRescanReport, FolderSourceFile,
    SOURCES, file_key, source_key, text_hash,
};
use crate::batch::secret_scan::{SecretScanMode, scan_write_payload, secret_scan_mode_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// How long the edit door may diff a changed file against its note.
const WHOLE_TEXT_TIMEOUT_MS: u32 = 2_000;

/// Where one source's files land: the folder its ledger is kept under, the
/// namespace its notes' ids derive from, and the world they are born in.
struct Landing<'a> {
    folder: &'a str,
    namespace: String,
    world: Option<EntityId>,
}

/// What holding one file by its name did.
enum Held {
    Unchanged,
    Named,
    /// Named, and the note its earlier text landed went to the archive.
    Archived,
    /// The write door's scan refused its path; no row was kept.
    Refused(String),
}

/// The ledger's meta for a file after a rescan read `facts` of it: none for
/// a folder attached as notes, which reads none.
fn next_meta(
    old: Option<FileMeta>,
    facts: Option<FileFacts>,
    at: u64,
    indexed_at: Option<u64>,
) -> Option<FileMeta> {
    match (old, facts) {
        (Some(old), Some(facts)) => Some(old.moved(facts, indexed_at)),
        (None, Some(facts)) => Some(FileMeta::first(facts, at, indexed_at)),
        (old, None) => old,
    }
}

impl Vault {
    /// One rescan of an attached folder: lands its new files, supersedes
    /// what its changed files landed, holds its files with no text by name
    /// and retracts what its missing files landed. A file the write door
    /// refuses is counted and tried again by the next rescan; the rest still
    /// land.
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
            name_only,
            missing,
            raw_hashes,
            facts,
        } = rescan;
        let key = source_key(&folder);
        let source = self
            .folder_source(&folder)?
            .ok_or_else(|| super::super::document::invalid("the folder is not attached"))?;
        owner.revalidate(self)?;
        let landing = Landing {
            folder: &folder,
            namespace: source.namespace(),
            world: source.files.as_ref().map(|files| files.world),
        };
        let mut report = FolderRescanReport::default();
        self.land_new_files(
            owner,
            &landing,
            new,
            links,
            (&raw_hashes, &facts),
            &mut report,
        )?;
        for file in &present {
            let raw_hash = raw_hashes.get(&file.path).cloned();
            let read = facts.get(&file.path).copied();
            self.rescan_present_file(&landing, file, raw_hash, read, &mut report)?;
        }
        for file in &name_only {
            self.hold_name_only_file(&landing, file, &mut report)?;
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
        landing: &Landing<'_>,
        notes: Vec<ImportedNote>,
        links: Vec<ImportedNoteLink>,
        read: (&HashMap<String, String>, &HashMap<String, FileFacts>),
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        if notes.is_empty() {
            return Ok(());
        }
        let batch = ImportedNoteBatch {
            request_id: self.new_entity_id()?,
            folder: landing.namespace.clone(),
            notes,
            links,
            name_only: Vec::new(),
        };
        match self.land_folder_batch(owner, landing, &batch, read) {
            Ok(links) => {
                report.landed += batch.notes.len();
                report.links += links;
                return Ok(());
            }
            Err(error) => {
                report.first_error.get_or_insert_with(|| error.to_string());
            }
        }
        let mut left_out = HashSet::new();
        for note in &batch.notes {
            let alone = ImportedNoteBatch {
                request_id: self.new_entity_id()?,
                folder: landing.namespace.clone(),
                notes: vec![note.clone()],
                links: Vec::new(),
                name_only: Vec::new(),
            };
            match self.land_folder_batch(owner, landing, &alone, read) {
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
                    &landing.namespace,
                    landing.world,
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
        landing: &Landing<'_>,
        batch: &ImportedNoteBatch,
        (raw_hashes, facts): (&HashMap<String, String>, &HashMap<String, FileFacts>),
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
                landing.world,
                &batch.notes,
                kinds,
                &ids,
                &batch.links,
            )?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            for (note, id) in batch.notes.iter().zip(&ids) {
                let key = file_key(landing.folder, &note.path);
                // A file held by its name until now keeps when it was first seen.
                let old = FILES.get(&self.store, txn, &key)?.and_then(|row| row.meta);
                let hash = text_hash(&note.markdown);
                let row = FolderSourceFile {
                    path: note.path.clone(),
                    note: Some(*id),
                    file_hash: hash.clone(),
                    landed_hash: hash,
                    raw_hash: raw_hashes.get(&note.path).cloned(),
                    state: FolderFileState::Landed,
                    meta: next_meta(old, facts.get(&note.path).copied(), at, Some(at)),
                    original: None,
                };
                FILES.put(&self.store, txn, &key, &row)?;
            }
            Ok(links)
        })
    }

    /// One file the folder still holds, against what its note holds.
    fn rescan_present_file(
        &self,
        landing: &Landing<'_>,
        file: &FolderFile,
        raw_hash: Option<String>,
        facts: Option<FileFacts>,
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        let key = file_key(landing.folder, &file.path);
        let id = Self::imported_note_id(&landing.namespace, &file.path)?;
        let hash = text_hash(&file.markdown);
        let (row, retracted) = {
            let txn = self.store.env.read_txn()?;
            let row = FILES.get(&self.store, &txn, &key)?;
            // The import archived the note: its file left, or had no text. A
            // row that names no note holds none the import archived.
            let retracted = row.as_ref().is_some_and(|row| {
                row.note.is_some()
                    && matches!(
                        row.state,
                        FolderFileState::Retracted | FolderFileState::NameOnly { .. }
                    )
            });
            if !retracted && let Some(same) = row.as_ref().filter(|row| row.file_hash == hash) {
                report.unchanged += 1;
                let facts_moved = facts.is_some_and(|facts| {
                    same.meta.is_none_or(|meta| {
                        (meta.bytes, meta.modified_at) != (facts.bytes, facts.modified_at)
                    })
                });
                if same.raw_hash == raw_hash && !facts_moved {
                    return Ok(());
                }
                // Only the bytes moved (a PDF's metadata, a file written again
                // with the same text): the ledger takes their revision, and
                // the note keeps its text.
                let mut same = same.clone();
                same.raw_hash = raw_hash;
                drop(txn);
                return self.with_write_txn(|txn| {
                    let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    let indexed_at = same.meta.and_then(|meta| meta.indexed_at);
                    same.meta = next_meta(same.meta, facts, at, indexed_at);
                    FILES.put(&self.store, txn, &key, &same)
                });
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
            note: Some(id),
            file_hash: String::new(),
            landed_hash: String::new(),
            raw_hash: None,
            state: FolderFileState::Landed,
            meta: None,
            original: None,
        });
        row.note = Some(id);
        row.raw_hash = raw_hash;
        if current == file.markdown {
            row.file_hash = hash.clone();
            row.landed_hash = hash;
            row.state = FolderFileState::Landed;
            if !retracted {
                report.unchanged += 1;
            }
            return self.with_write_txn(|txn| {
                let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                row.meta = next_meta(row.meta, facts, at, Some(at));
                FILES.put(&self.store, txn, &key, &row)
            });
        }
        // The note holds what the file gave it last (its first text, or a
        // later one the owner took from a fork): nothing of the owner's is
        // lost when the file's new text replaces it.
        let untouched = if row.landed_hash.is_empty() {
            let txn = self.store.env.read_txn()?;
            super::super::verbs::note_core(self, &txn, id)?
                .1
                .source_revision_ref
                == revision(&landing.namespace, &file.path, &current)
        } else {
            current_hash == row.landed_hash || current_hash == row.file_hash
        };
        let edit = if untouched {
            NoteProgramEdit::WholeText {
                text: file.markdown.clone(),
                timeout_ms: WHOLE_TEXT_TIMEOUT_MS,
                base: self.note_program_document(id)?.map(|doc| doc.version()),
            }
        } else {
            NoteProgramEdit::Rewrite {
                text: file.markdown.clone(),
            }
        };
        // The file's revision is the import's edit, never the owner's.
        let actor = WriteActor::new(
            Self::imported_note_author(&landing.namespace)?,
            EdgeActorClass::System,
        );
        let mut indexed = false;
        row.state = match self.edit_note(id, &edit, actor) {
            Ok(NoteProgramEditOutcome::Edited { .. }) => {
                report.superseded += 1;
                row.landed_hash = hash.clone();
                indexed = true;
                FolderFileState::Landed
            }
            Ok(
                NoteProgramEditOutcome::RewriteFork { fork }
                | NoteProgramEditOutcome::ProposedFork { fork },
            ) => {
                report.proposed += 1;
                FolderFileState::Proposed { fork: Some(fork) }
            }
            Ok(NoteProgramEditOutcome::ReviewRequired { .. }) => {
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
        self.with_write_txn(|txn| {
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let indexed_at = if indexed || retracted {
                Some(at)
            } else {
                row.meta.and_then(|meta| meta.indexed_at)
            };
            row.meta = next_meta(row.meta, facts, at, indexed_at);
            FILES.put(&self.store, txn, &key, &row)
        })
    }

    /// A file of a Files source with no text the vault takes: the ledger
    /// holds it by its name, and a note its earlier text landed goes to the
    /// archive until its text comes back. A path the vault never held is
    /// judged by the write door's scan as a new file's is; a refused one
    /// keeps no row.
    fn hold_name_only_file(
        &self,
        landing: &Landing<'_>,
        file: &NameOnlyFile,
        report: &mut FolderRescanReport,
    ) -> Result<()> {
        let key = file_key(landing.folder, &file.path);
        let state = FolderFileState::NameOnly { why: file.why };
        let held = self.with_write_txn(|txn| {
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let Some(mut row) = FILES.get(&self.store, txn, &key)? else {
                if secret_scan_mode_in_txn(&self.store, txn)? == SecretScanMode::On
                    && let Err(error) = scan_write_payload(file.path.as_bytes())
                {
                    return Ok(Held::Refused(error.to_string()));
                }
                let row = FolderSourceFile {
                    path: file.path.clone(),
                    note: None,
                    file_hash: String::new(),
                    landed_hash: String::new(),
                    raw_hash: None,
                    state,
                    meta: Some(FileMeta::first(file.facts, at, None)),
                    original: None,
                };
                FILES.put(&self.store, txn, &key, &row)?;
                return Ok(Held::Named);
            };
            let meta = next_meta(row.meta, Some(file.facts), at, None);
            if row.state == state && row.meta == meta {
                return Ok(Held::Unchanged);
            }
            let lost_text = matches!(
                row.state,
                FolderFileState::Landed | FolderFileState::Proposed { .. }
            );
            // A note the owner deleted or archived himself stays as he left
            // it: the ledger no longer names it, so no rescan restores it.
            if lost_text
                && let Some(note) = row.note
                && !self.archive_retracted_note_in_txn(txn, &note, at)?
            {
                row.note = None;
            }
            row.state = state;
            row.meta = meta;
            FILES.put(&self.store, txn, &key, &row)?;
            Ok(if lost_text {
                Held::Archived
            } else {
                Held::Named
            })
        })?;
        match held {
            Held::Unchanged => report.unchanged += 1,
            Held::Named => report.name_only += 1,
            Held::Archived => {
                report.name_only += 1;
                report.retracted += 1;
            }
            Held::Refused(error) => report.fail(error),
        }
        Ok(())
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
            // A name-only file's earlier note is in the archive already. A
            // note the owner deleted or archived himself stays as he left it:
            // the ledger no longer names it, so no rescan restores it.
            if !matches!(row.state, FolderFileState::NameOnly { .. })
                && let Some(note) = row.note
            {
                let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                if !self.archive_retracted_note_in_txn(txn, &note, at)? {
                    row.note = None;
                }
            }
            row.state = FolderFileState::Retracted;
            FILES.put(&self.store, txn, &key, &row)?;
            Ok(true)
        })?;
        report.retracted += usize::from(retracted);
        Ok(())
    }
}
