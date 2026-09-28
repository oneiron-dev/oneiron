//! Durable semantic NOTE requests for an authority-owned document subscription.
use super::DocumentRegistry;
use crate::note::{NoteOperation, NoteOperationReceipt};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::sync::transport::{decode_document, document_sub_tags, encode_document};
use crate::{EntityId, Result};

/// Durable pending semantic NOTE-operation request (`qn:e:{id}:{request_id}`).
/// Key: raw bytes (never decoded back to id/request by this door — see
/// `note::sync_rows::SYNC_QN_E`, the same shape).
const QN_E: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_QN_E);
/// Durable applied/rejected NOTE-operation receipt (`nc:e:{id}:{request_id}`).
/// Key: raw bytes; value: the receipt itself (see
/// `note::sync_rows::SYNC_NC_E`, the same shape, a generic `Value` there).
const NC_E: SideTable<Vec<u8>, NoteOperationReceipt, LegacyJson> =
    SideTable::new(&side_table::SYNC_NC_E);

impl DocumentRegistry {
    /// Queue an editor command without speculatively changing the canonical
    /// replica. Reconnect replays it until a durable per-request receipt arrives.
    /// A live socket sends it immediately; there is no save verb.
    pub fn submit_note(&self, id: EntityId, operation: &NoteOperation) -> Result<()> {
        let bytes = operation.encode()?;
        let frame = encode_document(id, document_sub_tags::NOTE_OPS, &bytes)
            .into_result()
            .map_err(|_| denied())?;
        self.vault.with_write_txn(|txn| {
            if self.vault.get_entity_type_in_txn(txn, &id)?
                != Some(crate::registry::ENTITY_TYPE_NOTE)
                || !super::DS_E.contains(&self.vault.store, txn, &crate::side_table::HexId(id))?
                || self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(txn, &id)?
            {
                return Err(denied());
            }
            crate::note::ensure_citations_ready(&self.vault.store, txn, id)?;
            if let crate::note::NoteChange::Cite { pin } = &operation.change {
                crate::note::validate_citation_dependencies(
                    &self.vault,
                    txn,
                    std::slice::from_ref(pin),
                )?;
            }
            // Also refuses soft-erased shells and malformed birth records.
            crate::note::document_birth_in_txn(&self.vault, txn, id)?;
            let key = format!("{}:{}", id.to_hex(), operation.request_id.to_hex()).into_bytes();
            if let Some(previous) = QN_E.get(&self.vault.store, txn, &key)?
                && previous != frame
            {
                return Err(denied());
            }
            QN_E.put(&self.vault.store, txn, &key, &frame)?;
            if let crate::note::NoteChange::Cite { pin } = &operation.change {
                crate::note::track_citation_request(
                    &self.vault.store,
                    txn,
                    id,
                    operation.request_id,
                    pin,
                )?;
            }
            Ok(())
        })?;
        let _ = self.notices.send(frame);
        Ok(())
    }

    pub(crate) fn pending_note_requests(&self, id: EntityId) -> Result<Vec<Vec<u8>>> {
        let txn = self.vault.store.env.read_txn()?;
        crate::note::ensure_citations_ready(&self.vault.store, &txn, id)?;
        Ok(QN_E
            .scan_from(
                &self.vault.store,
                &txn,
                format!("{}:", id.to_hex()).as_bytes(),
            )?
            .into_iter()
            .map(|(_, frame)| frame)
            .collect())
    }

    pub(crate) fn accept_note_receipt(
        &self,
        id: EntityId,
        receipt: &NoteOperationReceipt,
    ) -> Result<()> {
        self.vault.with_write_txn(|txn| {
            let key = format!("{}:{}", id.to_hex(), receipt.request_id.to_hex()).into_bytes();
            let Some(frame) = QN_E.get(&self.vault.store, txn, &key)? else {
                return Ok(());
            };
            let request = decode_document(&frame[1..]).map_err(|_| denied())?;
            let operation = NoteOperation::decode(request.payload)?;
            let digest = blake3::hash(&operation.encode()?);
            if digest.as_bytes() != &receipt.command_hash {
                return Err(denied());
            }
            crate::note::ensure_citations_ready(&self.vault.store, txn, id)?;
            if let crate::note::NoteEditOutcome::Applied(view) = &receipt.outcome {
                crate::note::validate_citation_dependencies(&self.vault, txn, &view.pins)?;
                if view.document != id {
                    return Err(denied());
                }
                let doc = super::storage::load(&self.vault, txn, id)?;
                let frontier = loro::Frontiers::decode(&view.frontier).map_err(|_| denied())?;
                if !matches!(
                    doc.cmp_frontiers(&doc.oplog_frontiers(), &frontier),
                    Ok(Some(
                        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater
                    ))
                ) {
                    return Err(denied());
                }
            }
            let nc_key = format!("{}:{}", id.to_hex(), receipt.request_id.to_hex()).into_bytes();
            NC_E.put(&self.vault.store, txn, &nc_key, receipt)?;
            QN_E.delete(&self.vault.store, txn, &key)?;
            crate::note::remove_citation_request(&self.vault.store, txn, id, receipt.request_id)?;
            Ok(())
        })
    }

    /// A receipt remains available after reconnect/reopen, including reviewed
    /// proposal outcomes whose text deliberately did not change.
    pub fn note_receipt(
        &self,
        id: EntityId,
        request: EntityId,
    ) -> Result<Option<NoteOperationReceipt>> {
        let txn = self.vault.store.env.read_txn()?;
        crate::note::ensure_citations_ready(&self.vault.store, &txn, id)?;
        let key = format!("{}:{}", id.to_hex(), request.to_hex()).into_bytes();
        NC_E.get(&self.vault.store, &txn, &key)
    }
}
fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
