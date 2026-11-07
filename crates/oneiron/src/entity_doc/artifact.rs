//! Proposal-text artifacts on the entity-document plane (FIX 11535): an
//! ED-00 artifact's own Loro document, with its birth, receipts and
//! operations, kept under an ordinary head of the artifact owner kind beside
//! the artifact's finalized record. The artifact has no ledger row, so its
//! head stands for it only while the record, read in the same transaction,
//! names that head; the doors that need a stored entity never reach it.

use heed::{RoTxn, RwTxn};

use super::storage::{self, DocumentOwnerKind, ENTITY_DOC_HEAD, Head, TextField};
use super::{EntityDoc, invalid};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot};
use crate::side_table::HexId;
use crate::store::Store;

/// `h`, the head stored under proposal artifact `artifact`'s id, when it is
/// of the artifact owner kind and the artifact's record names it in `txn`.
/// Any other head is not found.
pub(super) fn record_named_head(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    h: Head,
) -> Result<Head> {
    if h.entity != artifact.to_hex() {
        return Err(Error::CorruptedIndex("document head entity mismatch"));
    }
    let named = crate::edit_distance::artifact_head_incarnation_in_txn(store, txn, artifact)?;
    if h.owner_kind != DocumentOwnerKind::ProposalArtifact
        || named.as_deref() != Some(h.incarnation.as_str())
    {
        return Err(Error::EntityNotFound);
    }
    Ok(h)
}

/// Keeps `doc`, proposal artifact `artifact`'s own document, under a new
/// head of the artifact owner kind in its own slot, through the common
/// persistence seam, in the caller's transaction. Returns the head's
/// incarnation, for the artifact's record to name. The document is written
/// as it is, with its birth, receipts and operations: the finalize door has
/// already read what its texts hold, so no door scan runs here.
///
/// # Errors
///
/// A head already standing under `artifact`'s id, and storage errors.
pub(crate) fn put_artifact_document_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    artifact: &EntityId,
    doc: &EntityDoc,
) -> Result<EntityId> {
    if ENTITY_DOC_HEAD.contains(&vault.store, txn, &HexId(*artifact))? {
        return Err(invalid("entity already owns a document"));
    }
    let incarnation = EntityId::now();
    let mut h = Head {
        entity: artifact.to_hex(),
        owner_kind: DocumentOwnerKind::ProposalArtifact,
        incarnation: incarnation.to_hex(),
        document: artifact.to_hex(),
        field: TextField::Utf8Body,
        generation: 0,
        pending: 0,
        birth_frontier: None,
        // Born here fresh: no restore rebuilt it (FIX 3553).
        restored: None,
    };
    storage::persist_scanned(vault, txn, artifact, &mut h, doc, None, |_, _, _, _, _| {
        Ok(false)
    })?;
    Ok(incarnation)
}

/// The rows of a proposal artifact's document, read in one snapshot and
/// opened later, outside it.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactDocumentRows {
    /// The owner the head names, which the document's birth must name.
    owner: String,
    /// The slot's snapshot; `None` when the head stands without one.
    snapshot: Option<Vec<u8>>,
    /// The slot's pending updates, in replay order.
    updates: Vec<Vec<u8>>,
    /// How many pending updates the head counts.
    pending: u64,
}

impl ArtifactDocumentRows {
    /// The document the rows hold: the snapshot, then each update in order,
    /// checked as [`storage::load`] checks a head's document.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when the rows do not make the document the
    /// head names.
    pub(crate) fn open(&self) -> Result<EntityDoc> {
        let snapshot = self
            .snapshot
            .as_deref()
            .ok_or(Error::CorruptedIndex("entity document snapshot missing"))?;
        let doc = EntityDoc::from_snapshot(snapshot)?;
        if doc.birth().entity != self.owner {
            return Err(Error::CorruptedIndex("document birth entity mismatch"));
        }
        for update in &self.updates {
            let status = doc
                .doc
                .import(update)
                .map_err(|_| Error::CorruptedIndex("entity document update"))?;
            if status.pending.is_some() {
                return Err(Error::CorruptedIndex("entity document update dependencies"));
            }
        }
        if u64::try_from(self.updates.len()).ok() != Some(self.pending) {
            return Err(Error::CorruptedIndex("entity document update sequence"));
        }
        Ok(doc)
    }
}

/// The rows of proposal artifact `artifact`'s document under its head at
/// `incarnation`, read in the caller's snapshot. `None` when no such head
/// stands there: none at all, one that does not read, one of another owner
/// kind, or one at another incarnation.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn artifact_document_rows_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    incarnation: &str,
) -> Result<Option<ArtifactDocumentRows>> {
    let Some(h) = ENTITY_DOC_HEAD.get_lenient(store, txn, &HexId(*artifact))? else {
        return Ok(None);
    };
    if h.entity != artifact.to_hex()
        || h.owner_kind != DocumentOwnerKind::ProposalArtifact
        || h.incarnation != incarnation
    {
        return Ok(None);
    }
    let Ok(slot) = DocumentSlot::from_hex(&h.document) else {
        return Ok(None);
    };
    let snapshot = store.port_document_row(txn, slot, DocumentRow::Snapshot)?;
    let updates = store
        .port_document_updates(txn, slot)?
        .into_iter()
        .map(|update| update.bytes)
        .collect();
    Ok(Some(ArtifactDocumentRows {
        owner: h.entity,
        snapshot,
        updates,
        pending: h.pending,
    }))
}

/// Erases proposal artifact `artifact`'s document through the common erase,
/// in the caller's transaction: its head, its slot's rows, the pins to and
/// from it and its citation floors. Nothing is erased when no head of the
/// artifact owner kind stands under that id.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_artifact_document_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    artifact: &EntityId,
) -> Result<()> {
    match ENTITY_DOC_HEAD.get(store, txn, &HexId(*artifact))? {
        Some(h) if h.owner_kind == DocumentOwnerKind::ProposalArtifact => {
            storage::erase_in_txn(store, txn, artifact)
        }
        _ => Ok(()),
    }
}
