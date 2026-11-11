//! A NOTE's birth: its core row and its document, in one transaction.
//!
//! The row holds only the NOTE's immutable core (FIX 7783). The birth text
//! is the document's first commit, stamped with the core's author, and lives
//! nowhere else: no reader rebuilds a document from the row.
use super::document::NoteDocument;
use crate::batch::secret_scan::{Lifted, Part, admit_parts_in_txn};
use crate::store::ManifestDbs;
use crate::{EntityId, Result, Vault};

/// Where a NOTE's birth text's secrets were found, for their custody
/// records: the place its live text's are found (`document_store`).
const BIRTH_TEXT_PLACE: &str = "text:markdown";

/// Births the document of NOTE `id`, whose core row this transaction has
/// just put, from `text`, the NOTE's explicit birth text. The text is
/// admitted as a live write's text is (OF-067): with the owner's switch on,
/// each secret the batch door's text rules place goes to custody and the
/// text keeps its handle, before any history holds it. The deterministic
/// birth names the core's author; its snapshot, state vector, initial text
/// index entry and title reservation are written with the core.
///
/// No body length refuses a birth (rule 5, FIX 10345): a NOTE whose text
/// is past the text index's ceiling is born authoritative and unindexed, as
/// a large entity document is. A door that persists its NOTE after the
/// birth, as an edit does, meets the persist door's own refusals.
///
/// # Errors
///
/// A core that does not decode, a blank text, a hit no span places, and the
/// storage and title-reservation refusals of an authoritative NOTE write.
pub(crate) fn birth_document_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    text: &str,
) -> Result<()> {
    let (_, core) = super::verbs::note_core(vault, txn, id)?;
    super::validate_markdown(text)?;
    super::ensure_citations_ready(&vault.store, txn, id)?;
    let mut admitted = text.to_owned();
    admit_parts_in_txn(
        vault,
        txn,
        id,
        &mut [(BIRTH_TEXT_PLACE, Part::Text(&mut admitted))],
        &mut Lifted::default(),
    )?;
    let doc = NoteDocument::birth_by(id, &admitted, core.author_ref)?;
    super::storage::snapshot(vault, txn, id, &doc.doc, false)?;
    let fields = [(INDEX_FIELD.to_owned(), admitted)];
    if crate::store::text_index::check_indexed_text_bytes(&fields).is_ok() {
        vault
            .batch_in()
            .text(&id, &[(INDEX_FIELD, fields[0].1.as_str())])
            .apply(txn)?;
    }
    super::title_index::replace_authoritative_document_in_txn(vault, txn, &doc)
}

/// The text index field a NOTE's text is published under, as every persist
/// publishes its body (`revision::index_fields`). A NOTE is born with
/// no title or tags.
const INDEX_FIELD: &str = crate::config::bm25::NoteTextField::Body.source_name();

/// The NOTE document a room stages beside a NOTE it births (FIX 4280), as
/// the rows it stages: the deterministic birth of the row the room holds.
pub(crate) struct RoomBirthDocument {
    /// The document's snapshot row (`d:e:`).
    pub(crate) snapshot: Vec<u8>,
    /// Its state vector row (`sv:e:`).
    pub(crate) state_vector: Vec<u8>,
    /// Its body's UTF-8 bytes, which `EngineScan::NoteDocumentBytes` counts.
    pub(crate) body_bytes: usize,
}

/// [`RoomBirthDocument`] of `id` as `view`'s room holds its core, read in
/// the segment's transaction `txn`, born from `text`, the NOTE's explicit
/// birth text; `None` when the room holds no NOTE `id`.
///
/// # Errors
///
/// A stored NOTE core that does not decode; a document that does not
/// export.
pub(crate) fn room_birth_document_in_txn(
    vault: &Vault,
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    text: &str,
) -> Result<Option<RoomBirthDocument>> {
    let Some(doc) = born_in(vault, view, txn, id, text)? else {
        return Ok(None);
    };
    let snapshot = doc
        .export(loro::ExportMode::Snapshot)
        .map_err(|_| super::document::invalid("NOTE birth snapshot"))?;
    Ok(Some(RoomBirthDocument {
        snapshot,
        state_vector: doc.oplog_vv().encode(),
        body_bytes: super::document::document_sizes(&doc)[0],
    }))
}

/// The deterministic birth from `text` of the NOTE core `store` holds as
/// `id`; `None` when `store` holds no NOTE `id`.
fn born_in(
    vault: &Vault,
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    text: &str,
) -> Result<Option<loro::LoroDoc>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| super::document::invalid("NOTE entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    let (_, core) = super::verbs::note_core_in(vault, store, txn, id)?;
    // The birth records its stored author, live or erased (FIX 6072): the
    // seed is the same on every replica, and no writer is made from it.
    Ok(Some(NoteDocument::birth_by(id, text, core.author_ref)?.doc))
}
