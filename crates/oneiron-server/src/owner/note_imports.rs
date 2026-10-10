//! A folder of markdown notes as one import batch: preview its digest, then
//! approve or decline it whole (ARCH-0027, OF-202).
//!
//! `oneiron import notes` writes the batch to a file; the batch travels with
//! every call after that, as a claim batch does, so nothing staged can drift.
//! Approve is one engine transaction (the approve-once receipt, every note
//! and every link); decline writes a refusal receipt and admits nothing.
//! Either one is the batch's only decision.

use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{ImportedNote, ImportedNoteBatch, ImportedNoteLink, NOTES_IMPORT_SOURCE};
use oneiron::{EntityId, Vault};
use serde::{Deserialize, Serialize};

use super::{OwnerError, OwnerResult, entity_id};

/// One note on the wire.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoteFile {
    /// The file's path under the folder, `/`-separated.
    pub(crate) path: String,
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    /// When the file was last written, in seconds.
    pub(crate) written_at: u64,
    /// The file as written.
    pub(crate) markdown: String,
}

/// A link between two notes, by path under the folder.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoteLink {
    pub(crate) from: String,
    pub(crate) to: String,
}

/// A notes batch on the wire.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoteBatch {
    pub(crate) request_id: String,
    pub(crate) source_id: String,
    /// The folder the notes came from; with a note's path it names the note
    /// across imports.
    pub(crate) folder: String,
    pub(crate) notes: Vec<NoteFile>,
    pub(crate) links: Vec<NoteLink>,
}

/// What the owner is asked to approve.
#[derive(Debug, Serialize)]
pub(crate) struct NotePreview {
    /// Send this back with the batch to approve or decline it.
    pub(crate) digest: String,
    pub(crate) source_id: String,
    pub(crate) request_id: String,
    pub(crate) notes: usize,
    pub(crate) links: usize,
}

/// An approved batch.
#[derive(Debug, Serialize)]
pub(crate) struct NoteApproved {
    pub(crate) digest: String,
    pub(crate) approval: &'static str,
    pub(crate) request_id: String,
    pub(crate) notes: usize,
    pub(crate) links: usize,
}

/// A declined batch: one receipt, nothing admitted.
#[derive(Debug, Serialize)]
pub(crate) struct NoteDeclined {
    pub(crate) digest: String,
    pub(crate) decision_id: String,
    pub(crate) admitted: usize,
}

/// The digest of the exact batch.
pub(crate) fn preview(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: NoteBatch,
) -> OwnerResult<NotePreview> {
    let (source_id, request_id) = (batch.source_id.clone(), batch.request_id.clone());
    let exact = engine_batch(batch)?;
    Ok(NotePreview {
        digest: digest(vault, owner, &exact)?,
        source_id,
        request_id,
        notes: exact.notes.len(),
        links: exact.links.len(),
    })
}

/// The digest that approves or declines exactly `batch`.
pub(crate) fn digest(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: &ImportedNoteBatch,
) -> OwnerResult<String> {
    Ok(vault
        .imported_note_batch_effect(owner, batch)?
        .digest()
        .to_hex())
}

/// Lands every note and link of the previewed batch, in one transaction.
pub(crate) fn approve(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: NoteBatch,
    digest: &str,
) -> OwnerResult<NoteApproved> {
    let request_id = batch.request_id.clone();
    let exact = previewed(vault, owner, batch, digest)?;
    let receipt = vault.approve_imported_note_batch(owner, &exact)?;
    Ok(NoteApproved {
        digest: receipt.approval_digest,
        approval: "approved",
        request_id,
        notes: receipt.note_ids.len(),
        links: receipt.links,
    })
}

/// Refuses the whole previewed batch with one receipt; admits nothing.
pub(crate) fn decline(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: NoteBatch,
    digest: &str,
) -> OwnerResult<NoteDeclined> {
    let exact = previewed(vault, owner, batch, digest)?;
    let receipt = vault.decline_imported_note_batch(owner, &exact)?;
    Ok(NoteDeclined {
        digest: digest.to_owned(),
        decision_id: receipt.decision_id().to_hex(),
        admitted: 0,
    })
}

/// The engine batch, refused unless it is exactly the one the owner previewed.
fn previewed(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: NoteBatch,
    digest: &str,
) -> OwnerResult<ImportedNoteBatch> {
    let exact = engine_batch(batch)?;
    if self::digest(vault, owner, &exact)? != digest {
        return Err(OwnerError::Changed(
            "this batch is not the one that was previewed; import the folder again".into(),
        ));
    }
    Ok(exact)
}

/// The engine's batch, taking the wire batch's text rather than copying it.
pub(crate) fn engine_batch(batch: NoteBatch) -> OwnerResult<ImportedNoteBatch> {
    if batch.source_id != NOTES_IMPORT_SOURCE {
        return Err(OwnerError::Invalid(format!(
            "a notes batch has source_id {NOTES_IMPORT_SOURCE:?}"
        )));
    }
    let request_id: EntityId = entity_id("request_id", &batch.request_id)?;
    Ok(ImportedNoteBatch {
        request_id,
        folder: batch.folder,
        notes: batch
            .notes
            .into_iter()
            .map(|note| ImportedNote {
                path: note.path,
                kind: note.kind,
                title: note.title,
                written_at: note.written_at,
                markdown: note.markdown,
            })
            .collect(),
        links: batch
            .links
            .into_iter()
            .map(|link| ImportedNoteLink {
                from: link.from,
                to: link.to,
            })
            .collect(),
    })
}

/// The wire form of an engine batch, taking its text.
impl From<ImportedNoteBatch> for NoteBatch {
    fn from(batch: ImportedNoteBatch) -> Self {
        Self {
            request_id: batch.request_id.to_hex(),
            source_id: NOTES_IMPORT_SOURCE.to_owned(),
            folder: batch.folder,
            notes: batch
                .notes
                .into_iter()
                .map(|note| NoteFile {
                    path: note.path,
                    kind: note.kind,
                    title: note.title,
                    written_at: note.written_at,
                    markdown: note.markdown,
                })
                .collect(),
            links: batch
                .links
                .into_iter()
                .map(|link| NoteLink {
                    from: link.from,
                    to: link.to,
                })
                .collect(),
        }
    }
}
