//! A non-NOTE record's text on the sync plane (FIX 8871): the frames and the
//! local journal around its canonical entity document. The document is
//! `entity_doc`'s own, read durable inside each writer; nothing here keeps a
//! second copy of it, and a writer never overwrites a canonical edit with an
//! older copy.

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use super::{EntityDocument, QD_E, covers, eligible, storage};
use crate::entity_doc::SyncEdit;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::ports::DocumentSlot;
use crate::sync::transport::{decode_document, document_sub_tags, encode_document};
use crate::{EntityId, Vault};

/// `id`'s durable text and the slot its rows sit in: its document's, or its
/// sequence rows' for a kind with no birth here; an empty text in its own
/// slot for a MESSAGE not yet born.
pub(super) fn document_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: EntityId,
) -> Result<(LoroDoc, DocumentSlot)> {
    Ok(match crate::entity_doc::sync_text_in(vault, txn, &id)? {
        Some(text) => (text.doc, text.slot),
        None => (LoroDoc::new(), DocumentSlot::of(id)),
    })
}

/// `id`'s unacknowledged local edit frames, in commit order.
pub(super) fn journal_in(vault: &Vault, txn: &RoTxn<'_>, id: EntityId) -> Result<Vec<Vec<u8>>> {
    Ok(QD_E
        .scan_from(&vault.store, txn, journal_prefix(id).as_bytes())?
        .into_iter()
        .map(|(_, frame)| frame)
        .collect())
}

fn journal_prefix(id: EntityId) -> String {
    format!("{}:", id.to_hex())
}

/// The journal row of the edit of `sequence`, which a pending edit's key
/// spells as eight hex digits.
fn journal_key(id: EntityId, sequence: u64) -> Result<Vec<u8>> {
    let seq = u32::try_from(sequence)
        .map_err(|_| Error::InvariantViolation("document journal sequence overflow"))?;
    Ok(format!("{}:{seq:08x}", id.to_hex()).into_bytes())
}

fn denied() -> Error {
    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
}

impl EntityDocument {
    /// The writer of [`Self::edit_text`]: the edit, its journal row and its
    /// frame commit together; the notice and its prose receipts follow.
    pub(super) fn edit_record(&self, edit: &SyncEdit<'_>) -> Result<Vec<u8>> {
        let _writer = self.lock()?;
        let (frame, edited) = self.vault.with_write_txn_grouped(|txn| {
            eligible(&self.vault, txn, self.id)?;
            let edited =
                crate::entity_doc::edit_sync_text_in_txn(&self.vault, txn, &self.id, edit)?;
            let frame = encode_document(self.id, document_sub_tags::UPDATE, &edited.update)
                .into_result()
                .map_err(|_| Error::InvariantViolation("document edit exceeds wire limit"))?;
            let key = journal_key(self.id, edited.sequence)?;
            QD_E.put(&self.vault.store, txn, &key, &frame)?;
            Ok((frame, edited))
        })?;
        let _ = self.notices.send(frame.clone());
        edited.land(&self.vault);
        Ok(frame)
    }

    /// The writer of a peer's or an authority's text: `admit` judges it in
    /// the same transaction, then an UPDATE joins the document and a STATE
    /// replaces it.
    pub(super) fn import_record(
        &self,
        kind: u8,
        bytes: &[u8],
        admit: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        let _writer = self.lock()?;
        self.vault.with_write_txn_grouped(|txn| {
            eligible(&self.vault, txn, self.id)?;
            if self.vault.get_entity_type_in_txn(txn, &self.id)?
                == Some(crate::registry::ENTITY_TYPE_NOTE)
            {
                return Err(denied());
            }
            admit(txn)?;
            match kind {
                document_sub_tags::UPDATE => {
                    crate::entity_doc::join_sync_update_in_txn(
                        &self.vault,
                        txn,
                        &self.id,
                        bytes,
                        None,
                    )?;
                    Ok(())
                }
                document_sub_tags::STATE => self.replace_in_txn(txn, bytes),
                _ => Err(denied()),
            }
        })
    }

    /// STATE replaces, never merges a shallow copy: the state, with each
    /// pending local update replayed on it, must cover the durable text, or
    /// nothing changes.
    fn replace_in_txn(&self, txn: &mut RwTxn<'_>, bytes: &[u8]) -> Result<()> {
        let staged = LoroDoc::new();
        storage::import_complete(&staged, bytes)?;
        for frame in journal_in(&self.vault, txn, self.id)? {
            let frame = decode_document(&frame[1..])
                .map_err(|_| Error::sync_protocol(SyncProtocolValidation::InvalidDocumentKey))?;
            storage::import_complete(&staged, frame.payload)?;
        }
        let (held, _) = document_in(&self.vault, txn, self.id)?;
        if !covers(&staged.oplog_vv(), &held.oplog_vv()) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentPendingUpdate,
            ));
        }
        crate::entity_doc::replace_sync_text_in_txn(&self.vault, txn, &self.id, staged)
    }

    /// Clears the journal once `remote` holds every operation of the durable
    /// text, read in the clearing writer.
    pub(super) fn acknowledge_record(&self, remote: &loro::VersionVector) -> Result<()> {
        let _writer = self.lock()?;
        self.vault.with_write_txn_grouped(|txn| {
            let (held, _) = document_in(&self.vault, txn, self.id)?;
            if !covers(remote, &held.oplog_vv()) {
                return Ok(());
            }
            let keys: Vec<Vec<u8>> =
                QD_E.scan_keys(&self.vault.store, txn, journal_prefix(self.id).as_bytes())?;
            for key in keys {
                QD_E.delete(&self.vault.store, txn, &key)?;
            }
            Ok(())
        })
    }
}
