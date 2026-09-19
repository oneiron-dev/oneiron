//! Durable semantic NOTE requests for an authority-owned document subscription.
use super::DocumentRegistry;
use crate::note::{NoteOperation, NoteOperationReceipt};
use crate::sync::transport::{decode_document, document_sub_tags, encode_document};
use crate::{EntityId, Result};

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
                || self
                    .vault
                    .store
                    .sync_state
                    .get(txn, &format!("ds:e:{}", id.to_hex()))?
                    .is_none()
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
            let key = format!("qn:e:{}:{}", id.to_hex(), operation.request_id.to_hex());
            if let Some(previous) = self.vault.store.sync_state.get(txn, &key)? {
                if previous.as_ref() != frame.as_slice() {
                    return Err(denied());
                }
            }
            self.vault.store.sync_state.put(txn, &key, &frame)?;
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
        self.vault
            .store
            .sync_state
            .prefix_iter(&txn, &format!("qn:e:{}:", id.to_hex()))?
            .map(|row| row.map(|(_, frame)| frame.to_vec()))
            .collect()
    }

    pub(crate) fn accept_note_receipt(
        &self,
        id: EntityId,
        receipt: &NoteOperationReceipt,
    ) -> Result<()> {
        self.vault.with_write_txn(|txn| {
            let key = format!("qn:e:{}:{}", id.to_hex(), receipt.request_id.to_hex());
            let Some(frame) = self.vault.store.sync_state.get(txn, &key)? else {
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
            let bytes = serde_json::to_vec(receipt).map_err(|_| denied())?;
            self.vault.store.sync_state.put(
                txn,
                &format!("nc:e:{}:{}", id.to_hex(), receipt.request_id.to_hex()),
                &bytes,
            )?;
            self.vault.store.sync_state.delete(txn, &key)?;
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
        self.vault
            .store
            .sync_state
            .get(&txn, &format!("nc:e:{}:{}", id.to_hex(), request.to_hex()))?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| denied()))
            .transpose()
    }
}
fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
