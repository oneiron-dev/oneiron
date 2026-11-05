//! Stored native NOTE slots used by exact indexed and retained revision reads.

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, UpdateSeq};
use crate::store::ManifestDbs;
use loro::{Frontiers, LoroDoc, VersionVector};

pub(crate) struct StoredNoteSlot {
    pub(crate) doc: LoroDoc,
    floor: Option<VersionVector>,
}

impl StoredNoteSlot {
    pub(crate) fn retains(&self, frontier: &Frontiers) -> bool {
        let vv = if self.doc.oplog_frontiers() == *frontier {
            Some(self.doc.oplog_vv())
        } else {
            self.doc.frontiers_to_vv(frontier)
        };
        vv.is_some_and(|vv| {
            vv.includes_vv(&self.doc.shallow_since_vv().to_vv())
                && self
                    .floor
                    .as_ref()
                    .is_none_or(|floor| vv.includes_vv(floor))
        })
    }

    pub(crate) fn cut_past(&self, frontier: &Frontiers) -> bool {
        if self.retains(frontier) {
            return false;
        }
        let covers = |floor: &VersionVector| {
            !frontier.is_empty() && frontier.iter().all(|id| floor.includes_id(id))
        };
        covers(&self.doc.shallow_since_vv().to_vv()) || self.floor.as_ref().is_some_and(covers)
    }

    pub(crate) fn at(self, frontier: &[u8]) -> Result<LoroDoc> {
        let frontier = super::document::frontier(frontier)?;
        if !self.retains(&frontier) {
            return Err(Error::EntityNotFound);
        }
        if self.doc.oplog_frontiers() == frontier {
            Ok(self.doc)
        } else {
            self.doc
                .fork_at(&frontier)
                .map_err(|_| Error::EntityNotFound)
        }
    }
}

/// No birth fallback: an indexed binding names an actual stored slot, not a
/// reconstruction from today's core or the NOTE's current head.
pub(crate) fn stored_slot_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    slot: EntityId,
) -> Result<Option<StoredNoteSlot>> {
    let slot = DocumentSlot::of(slot);
    let Some(bytes) = store.port_document_row(txn, slot, DocumentRow::Snapshot)? else {
        return Ok(None);
    };
    let doc = LoroDoc::new();
    super::storage::import_complete(&doc, &bytes)?;
    for update in store.port_document_updates(txn, slot)? {
        if !matches!(update.seq, Some(UpdateSeq::Sequence(_))) {
            return Err(super::document::invalid(
                "invalid canonical document update key",
            ));
        }
        super::storage::import_complete(&doc, &update.bytes)?;
    }
    let canonical = super::document::NoteDocument::from_loro(note, doc)?;
    let floor = store
        .port_document_row(txn, slot, DocumentRow::ShallowSince)?
        .map(|bytes| {
            VersionVector::decode(&bytes)
                .map_err(|_| super::document::invalid("NOTE stored shallow frontier"))
        })
        .transpose()?;
    super::scan::measure_document(
        store,
        txn,
        note,
        &canonical.doc,
        store.pending_scan_checks(),
    )?;
    Ok(Some(StoredNoteSlot {
        doc: canonical.doc,
        floor,
    }))
}

/// The selected native prose shares the historical physical row's metadata;
/// no frontier entry keeps another copy of the NOTE core or its author.
pub(crate) fn row_with_markdown_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    raw: &[u8],
    markdown: String,
) -> Result<Vec<u8>> {
    let header = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("NOTE revision entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_NOTE {
        return Err(Error::CorruptedIndex("NOTE revision entity type"));
    }
    let mut body = super::decode_note_body_in_txn(store, txn, &raw[ENTITY_METADATA_HEADER_LEN..])?;
    body.markdown = markdown;
    let mut selected = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
    selected.extend_from_slice(&super::encode_note_body(&body)?);
    Ok(selected)
}

/// Indexes the actual stored image. The optional closed replay grant is the
/// same admission the caller used for its selected save, never a new mint.
pub(super) fn index_stored_note_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    grant: Option<&crate::off_record::promote::PromoteReplayGrant>,
) -> Result<()> {
    let capture = crate::vault::entity_revision::capture_native_note_in_txn(vault, txn, note)?;
    if capture.changed || capture.published {
        let batch = match grant {
            Some(grant) => crate::batch::BatchBuilder::promotion_replay(vault, Vec::new(), grant),
            None => vault.batch_in(),
        };
        batch
            .text(&note, &[("markdown", capture.markdown.as_str())])
            .apply(txn)?;
    }
    if capture.published {
        crate::vault::entity_revision::finish_native_note_publication_in_txn(vault, txn, note)?;
    }
    Ok(())
}
