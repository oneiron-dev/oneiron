//! Whole-vault archive import of NOTE rows (FIX 7777).
//!
//! An archive carries every NOTE with its current markdown. An import
//! brings it back as imported evidence, never as a note this vault's actor
//! wrote: the source author stays in `author_ref` as
//! [`NoteActor::Imported`], which matches no local writer and opens no
//! author-only read or edit. No `AuthoredBy` edge, stamp token, document
//! operation or title, pin or seal is written. A NOTE an import already
//! marked, or whose author was erased, comes back as it is.
//!
//! [`ArchivedNoteAdmission`] is the archive NOTE put's capability: its one
//! constructor proves the bytes are a NOTE body under the pinned ABI whose
//! author is no local actor.
//!
//! An imported diary or owner-only NOTE has no local author to read it, so
//! every ordinary read, search and context pack holds it. The vault's
//! current owner reads one only by asking for it by id through
//! [`Vault::read_imported_note`], an explicit owner act.

use serde::Serialize;

use super::{NoteActor, NoteBody, NoteKind, decode_note_body_using};
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::store::note_body::encode_note_body;
use crate::temporal::TimeRange;

/// What the vault's current owner reads of an imported NOTE
/// ([`Vault::read_imported_note`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedNoteRead {
    /// The NOTE's kind, as its body stores it.
    pub kind: String,
    /// The author the source vault recorded, as a hex id: provenance, never
    /// a local actor.
    pub source_author: String,
    /// Its current markdown.
    pub markdown: String,
}

/// One archived NOTE body the archive put may stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchivedNoteAdmission {
    body: Vec<u8>,
    markdown: String,
}

impl ArchivedNoteAdmission {
    /// The proven body bytes, and nothing else.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}

fn decode(bytes: &[u8]) -> Result<NoteBody> {
    decode_note_body_using(bytes, NoteKind::wire)
}

/// The body an archived NOTE comes back with: `source`, its archived body,
/// with a local author kept as [`NoteActor::Imported`]. An erased or
/// already imported author, and every other field, stays as it is.
///
/// # Errors
/// [`RecordError::InvalidNoteBody`] when `source` is not a NOTE body under
/// the pinned ABI.
pub(crate) fn archived_note_body(source: &[u8]) -> Result<Vec<u8>> {
    let mut body = decode(source)?;
    let NoteActor::Actor(author) = body.author_ref else {
        return Ok(source.to_vec());
    };
    body.author_ref = NoteActor::Imported(author);
    encode_note_body(&body)
}

/// The archive NOTE put's capability for `body`: a NOTE body under the
/// pinned ABI whose author is no local actor.
fn admit_archived_note(body: &[u8]) -> Result<ArchivedNoteAdmission> {
    let decoded = decode(body)?;
    if matches!(decoded.author_ref, NoteActor::Actor(_)) {
        return Err(refused(
            "an archived NOTE is restored only with an imported author",
        ));
    }
    if encode_note_body(&decoded)? != body {
        return Err(refused("an archived NOTE body is not canonical"));
    }
    Ok(ArchivedNoteAdmission {
        body: body.to_vec(),
        markdown: decoded.markdown,
    })
}

impl Vault {
    /// The vault's current owner reads imported NOTE `note` (FIX 7777),
    /// whatever its kind's read context: an imported diary or owner-only
    /// NOTE, which every ordinary read and search holds, reads here to the
    /// owner who names it. `None` when `note` names no live NOTE with an
    /// imported author, or one kept under a use limit.
    ///
    /// # Errors
    /// The owner proof's refusal (another vault's, a lapsed credential, not
    /// an owner); a stored NOTE that does not decode; storage faults.
    pub fn read_imported_note(
        &self,
        owner: &AuthenticatedOwner,
        note: &EntityId,
    ) -> Result<Option<ImportedNoteRead>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if crate::vault::live_entity_row_in_txn(&self.store, &txn, note)?.live_type()
            != Some(ENTITY_TYPE_NOTE)
        {
            return Ok(None);
        }
        // A record kept under a use limit (a legal hold or a cooperative
        // review restriction) reads to no one here, its owner included, as
        // every ordinary read refuses it.
        if crate::store::legal_hold::use_limit_in_txn(&self.store, &txn, note)?.is_some() {
            return Ok(None);
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, note)?
        else {
            return Ok(None);
        };
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        let NoteActor::Imported(author) = decode(body)?.author_ref else {
            return Ok(None);
        };
        let live = super::live_body_in_txn(&self.store, &txn, note, ENTITY_TYPE_NOTE, body)?;
        let live = decode(&live)?;
        Ok(Some(ImportedNoteRead {
            kind: live.kind.as_str().into_owned(),
            source_author: author.to_hex(),
            markdown: live.markdown,
        }))
    }

    /// Restores one archived NOTE in the import's writer (FIX 7777): the
    /// row through the archive put, born under `mask` (its archived facet,
    /// or the vault default when `None`), and its markdown's text posting.
    /// Its kind's installed descriptor and its immutable birth bytes are
    /// checked where every NOTE put meets them. Nothing binds an actor or
    /// mints authorship.
    ///
    /// # Errors
    /// The admission's refusal; the NOTE put's refusals; storage faults.
    pub(crate) fn restore_archived_note_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &[u8],
        occurred: TimeRange,
        learned_at: u64,
        mask: Option<EntityId>,
    ) -> Result<()> {
        let admission = admit_archived_note(body)?;
        let mut batch = self
            .batch_in()
            .mask(mask)
            .put_archived_note(id, occurred, learned_at, &admission);
        if !admission.markdown.is_empty() {
            batch = batch.text(id, &[("markdown", admission.markdown.as_str())]);
        }
        batch.apply(wtxn)
    }
}
