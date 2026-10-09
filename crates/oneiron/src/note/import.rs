//! A folder of linked markdown notes, imported as one batch the owner
//! approves or declines whole (ARCH-0027 import pipeline, ARCH-0032 notes).
//!
//! The host reads the folder and resolves each note's links; this module
//! fixes the batch's digest and lands it. Each file becomes a NOTE whose id
//! derives from the folder and the file's path, so a re-import finds the
//! notes an earlier one landed and adds nothing for them. Each resolved link
//! becomes a `mentions` edge between the two notes. Approve is one write
//! transaction: the approve-once receipt, the batch's decision slot, every
//! note and every link. Decline is a denial receipt and admits nothing.

use std::collections::{HashMap, HashSet};

use super::{NoteBody, encode_note_body};
use crate::batch::secret_scan::{SecretScanMode, scan_write_payload, secret_scan_mode_in_txn};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, ConsentReceipt,
    EffectFacts, GrantBound,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::derived_domains;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};

/// The registered ingest source a notes import enters under.
pub const NOTES_IMPORT_SOURCE: &str = "markdown";

const REVIEW: &str = "notes.import.review";

/// The longest path a note keeps as its name in the folder.
const MAX_PATH_BYTES: usize = 4096;

/// One file of the folder, as it will land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedNote {
    /// The file's path under the folder, `/`-separated. With the folder it
    /// names the note across imports.
    pub path: String,
    /// A note kind the vault knows.
    pub kind: String,
    pub title: Option<String>,
    /// When the file was last written (seconds): the note's valid time.
    pub written_at: u64,
    /// The file as written.
    pub markdown: String,
}

/// A link from one note to another, by path under the folder. Either end may
/// be a note an earlier import of the same folder landed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportedNoteLink {
    pub from: String,
    pub to: String,
}

/// The exact batch; a new request id needs a new owner decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedNoteBatch {
    pub request_id: EntityId,
    /// The folder the notes came from, as the host names it.
    pub folder: String,
    pub notes: Vec<ImportedNote>,
    pub links: Vec<ImportedNoteLink>,
}

/// An approved batch: what landed, under the digest the owner approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedNoteBatchReceipt {
    pub approval_digest: String,
    pub note_ids: Vec<EntityId>,
    pub links: usize,
}

/// Where one file stands against the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportedNoteStanding {
    /// No import landed it yet.
    New,
    /// An import landed exactly this text.
    Unchanged,
    /// An import landed an earlier text; the note is left as it is.
    Changed,
    /// The note it became was deleted or archived; it is not imported again.
    Removed,
    /// New, but the write door's secret scan would refuse its text.
    Refused,
}

impl Vault {
    /// The id the file at `path` under `folder` lands as.
    ///
    /// # Errors
    /// Only if id derivation fails.
    pub fn imported_note_id(folder: &str, path: &str) -> Result<EntityId> {
        EntityId::derive(
            derived_domains::IMPORTED_NOTE,
            &[folder.as_bytes(), path.as_bytes()],
        )
    }

    /// Where each `(path, markdown)` of `folder` stands against the vault.
    ///
    /// # Errors
    /// A storage error, or an id that is taken by something other than a NOTE.
    pub fn imported_note_standings(
        &self,
        folder: &str,
        files: &[(&str, &str)],
    ) -> Result<Vec<ImportedNoteStanding>> {
        let txn = self.store.env.read_txn()?;
        let scanning = secret_scan_mode_in_txn(&self.store, &txn)? == SecretScanMode::On;
        files
            .iter()
            .map(|(path, markdown)| {
                let id = Self::imported_note_id(folder, path)?;
                // Deleted (its shell kept, or purged) or archived.
                let raw = self.get_raw_in(&txn, &id)?;
                if crate::deletion::row_deletion_marked(&self.store, &txn, &id, raw.as_deref())?
                    || self.archive_tombstone_in_txn(&txn, &id)?.is_some()
                {
                    return Ok(ImportedNoteStanding::Removed);
                }
                match self.get_entity_type_in_txn(&txn, &id)? {
                    None if scanning && scan_write_payload(markdown.as_bytes()).is_err() => {
                        Ok(ImportedNoteStanding::Refused)
                    }
                    None => Ok(ImportedNoteStanding::New),
                    Some(ENTITY_TYPE_NOTE) => {
                        let (_, core) = super::verbs::note_core(self, &txn, id)?;
                        Ok(
                            if core.source_revision_ref == revision(folder, path, markdown) {
                                ImportedNoteStanding::Unchanged
                            } else {
                                ImportedNoteStanding::Changed
                            },
                        )
                    }
                    Some(_) => Err(Error::InvalidClaimBody(
                        "an imported note id is taken by another entity",
                    )),
                }
            })
            .collect()
    }

    /// Whether `title` is free among the notes `owner` wrote. Titles that
    /// differ only in case and spacing are one title.
    ///
    /// # Errors
    /// A storage error.
    pub fn note_title_free(&self, owner: &AuthenticatedOwner, title: &str) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(super::title_index::holder_in_txn(&self.store, &txn, owner.actor(), title)?.is_none())
    }

    /// The exact batch, described for one approve-once act of `owner`.
    /// Changing any note, link, kind, title, time or the request changes the
    /// digest.
    ///
    /// # Errors
    /// Refuses an empty batch, a repeated path or title, a blank or oversize
    /// note, an invalid title and a link that is not between two paths.
    pub fn imported_note_batch_effect(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedNoteBatch,
    ) -> Result<ComposedEffect> {
        validate_batch(batch)?;
        let bound = GrantBound::action(
            ActorBound::new(owner.actor().to_hex())?,
            ActionClass::new(REVIEW)?,
            ActionEnvelope::new([
                format!("request:{}", batch.request_id.to_hex()),
                format!("source:{NOTES_IMPORT_SOURCE}"),
                format!("notes:{}", batch.notes.len()),
                format!("links:{}", batch.links.len()),
                format!("content:{}", content_hash(batch)?.to_hex()),
            ])?,
        )?;
        ComposedEffect::new(EffectFacts::new(REVIEW)?).with_action_requirement(bound)
    }

    /// The owner's one act for the whole batch: the approve-once receipt,
    /// every note with its title and every link commit in one write
    /// transaction, or none does.
    ///
    /// # Errors
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when any owner already approved or declined this exact batch; an
    /// error when a note's id is no longer new, a link's end is not a note,
    /// a kind is unknown or a title is taken. Nothing lands then.
    pub fn approve_imported_note_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedNoteBatch,
    ) -> Result<ImportedNoteBatchReceipt> {
        let digest = self.imported_note_batch_effect(owner, batch)?.digest();
        let slot = decision_slot(batch)?;
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
        let actor = WriteActor::new(owner.actor(), EdgeActorClass::Human);
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let receipt = self.approve_once_in_txn(txn, owner, digest)?;
            self.take_decision_slot_in_txn(txn, &slot, receipt.decision_id())?;
            for id in &ids {
                if self.local_hard_delete_marker_exists_in_txn(txn, id)?
                    || self.get_raw_in(txn, id)?.is_some()
                {
                    return Err(super::document::invalid(
                        "an imported note is no longer new; preview the folder again",
                    ));
                }
            }
            let landing: HashMap<&str, EntityId> = batch
                .notes
                .iter()
                .zip(&ids)
                .map(|(note, id)| (note.path.as_str(), *id))
                .collect();
            let read: &heed::RoTxn<'_> = txn;
            let end = |path: &str| -> Result<EntityId> {
                if let Some(id) = landing.get(path) {
                    return Ok(*id);
                }
                let id = Self::imported_note_id(&batch.folder, path)?;
                super::verbs::note_core(self, read, id)
                    .map(|_| id)
                    .map_err(|_| {
                        super::document::invalid(
                            "a linked note is not in the vault; preview the folder again",
                        )
                    })
            };
            let edges = batch
                .links
                .iter()
                .map(|link| Ok((end(&link.from)?, end(&link.to)?)))
                .collect::<Result<Vec<_>>>()?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut content = crate::federation::ActorContentTxn::new(self, txn, actor)?;
            for ((note, kind), id) in batch.notes.iter().zip(kinds).zip(&ids) {
                let body = encode_note_body(&NoteBody {
                    kind,
                    author_ref: owner.actor(),
                    markdown: note.markdown.clone(),
                    source_revision_ref: revision(&batch.folder, &note.path, &note.markdown),
                })?;
                let written = if note.written_at == 0 {
                    at
                } else {
                    note.written_at
                };
                content.apply_batch(
                    self.batch_in()
                        .put_authored_note(
                            id,
                            &owner.actor(),
                            TimeRange {
                                start: written,
                                end: written,
                            },
                            at,
                            &body,
                        )
                        .edge(id, EdgeKind::AuthoredBy, &owner.actor(), 1.0),
                )?;
                content.update_note(*id, |txn| {
                    let doc = super::document_store::load(self, txn, *id)?;
                    if let Some(title) = &note.title {
                        doc.set_title(title, &actor)?;
                        super::operations::record_authorship(
                            &doc,
                            &super::NoteAuthorship {
                                operation: self.new_entity_id()?,
                                actor: owner.actor(),
                                actor_class: EdgeActorClass::Human.gate_actor_class().to_owned(),
                                grant: None,
                                command_hash: *blake3::hash(title.as_bytes()).as_bytes(),
                            },
                        )?;
                    }
                    super::document_store::persist_authoritative(self, txn, &doc)
                })?;
            }
            if !edges.is_empty() {
                let mut links = self.batch_in();
                for (from, to) in &edges {
                    links = links.edge(from, EdgeKind::Mentions, to, 1.0);
                }
                content.apply_batch(links)?;
            }
            content.finish()?;
            drop(content);
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &digest)?
                    .ok_or(Error::CorruptedIndex("consent approve-once marker"))?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &authorization)?;
            Ok(ImportedNoteBatchReceipt {
                approval_digest: digest.to_hex(),
                note_ids: ids.clone(),
                links: edges.len(),
            })
        })
    }

    /// The owner's refusal of the whole batch: one denial receipt, nothing
    /// admitted. It takes the batch's one decision slot, so it is final.
    ///
    /// # Errors
    /// [`GateError::ConsentApproveOnceSpent`](crate::error::GateError::ConsentApproveOnceSpent)
    /// when any owner already approved or declined this exact batch.
    pub fn decline_imported_note_batch(
        &self,
        owner: &AuthenticatedOwner,
        batch: &ImportedNoteBatch,
    ) -> Result<ConsentReceipt> {
        let digest = self.imported_note_batch_effect(owner, batch)?.digest();
        let slot = decision_slot(batch)?;
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let receipt = self.deny_consent_in_txn(txn, owner, digest)?;
            self.take_decision_slot_in_txn(txn, &slot, receipt.decision_id())?;
            Ok(receipt)
        })
    }
}

/// The NOTE body's source revision: which text of which file landed. A
/// re-import compares it, so later edits to the note do not read as a
/// changed file.
fn revision(folder: &str, path: &str, markdown: &str) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron notes.import revision v1");
    for part in [folder, path, markdown] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut out = [0; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    out
}

/// Every note and link of the batch, hashed.
fn content_hash(batch: &ImportedNoteBatch) -> Result<blake3::Hash> {
    let notes = batch
        .notes
        .iter()
        .map(|note| {
            (
                &note.path,
                &note.kind,
                &note.title,
                note.written_at,
                blake3::hash(note.markdown.as_bytes()).to_hex().to_string(),
            )
        })
        .collect::<Vec<_>>();
    let links = batch
        .links
        .iter()
        .map(|link| (&link.from, &link.to))
        .collect::<Vec<_>>();
    let content = serde_json::to_vec(&(&batch.folder, notes, links))
        .map_err(|_| Error::InvalidClaimBody("note import batch encoding failed"))?;
    Ok(blake3::hash(&content))
}

/// The batch's one decision slot, whichever owner decides.
fn decision_slot(batch: &ImportedNoteBatch) -> Result<[u8; 32]> {
    let named = serde_json::to_vec(&(
        batch.request_id.to_hex(),
        NOTES_IMPORT_SOURCE,
        batch.notes.len(),
        batch.links.len(),
        content_hash(batch)?.to_hex().as_str(),
    ))
    .map_err(|_| Error::InvalidClaimBody("note import batch encoding failed"))?;
    let mut hasher = blake3::Hasher::new_derive_key("oneiron notes.import.review decision v1");
    hasher.update(&named);
    Ok(*hasher.finalize().as_bytes())
}

fn validate_batch(batch: &ImportedNoteBatch) -> Result<()> {
    let invalid = super::document::invalid;
    if crate::ingest::INGEST_SOURCE_REGISTRY
        .get_config(NOTES_IMPORT_SOURCE)
        .is_none_or(|config| config.writes_claims)
    {
        return Err(invalid("the markdown import source is not registered"));
    }
    if batch.notes.is_empty() {
        return Err(invalid("empty note import batch"));
    }
    if batch.folder.trim().is_empty() {
        return Err(invalid("a note import batch names its folder"));
    }
    let mut paths = HashSet::new();
    let mut titles = HashSet::new();
    for note in &batch.notes {
        if note.path.is_empty() || note.path.len() > MAX_PATH_BYTES {
            return Err(invalid("an imported note's path is empty or too long"));
        }
        if !paths.insert(note.path.as_str()) {
            return Err(invalid("a path appears twice in the note import batch"));
        }
        super::validate_markdown(&note.markdown)?;
        if note.markdown.len() > super::document::MAX_NOTE_BYTES {
            return Err(invalid("NOTE body exceeds bound"));
        }
        if let Some(title) = &note.title {
            super::document::validate_title(title)?;
            if !titles.insert(super::title_index::normalized(title)) {
                return Err(invalid("a title appears twice in the note import batch"));
            }
        }
    }
    let mut links = HashSet::new();
    for link in &batch.links {
        if link.from.is_empty() || link.to.is_empty() || link.from == link.to {
            return Err(invalid("an imported link joins two different notes"));
        }
        if !links.insert(link) {
            return Err(invalid("a link appears twice in the note import batch"));
        }
    }
    Ok(())
}
