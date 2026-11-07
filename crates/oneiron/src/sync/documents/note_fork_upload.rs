//! An own device's queue of replica-local NOTE forks for the NOTE's
//! authority (FIX 12789), beside its queued NOTE commands.
//!
//! The queue keeps each upload's marker under the NOTE and the fork: the
//! fork's id, parent head, frontier and rewrite flag, with no text. Each
//! send, a live one or a reconnect's replay, reads the fork's own operations
//! from the fork as it then stands, so an erase that takes the fork leaves
//! nothing of it queued; a fork no longer uploadable (decided, bundled or
//! erased) sends nothing. The authority's receipt settles the marker: an
//! accepted fork is stored there, pending; a refused one stays on this
//! device only.

use super::DocumentRegistry;
use crate::note::{
    NoteForkUpload, NoteForkUploadOutcome, NoteForkUploadReceipt, PendingNoteRequest,
};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::sync::transport::{decode_document, document_sub_tags, encode_document};
use crate::{EntityId, Result};

/// The queued NOTE requests (`qn:e:{note}:{request}`), the same family the
/// NOTE command queue keeps; a fork upload's request id is its fork.
const QN_E: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_QN_E);

impl DocumentRegistry {
    /// Queues the replica-local fork `fork` of the NOTE `id` for the NOTE's
    /// authority, and sends it at once on a live socket. Reconnect sends it
    /// again until the authority's receipt arrives. Queuing the same fork
    /// again keeps its one place.
    ///
    /// # Errors
    ///
    /// A NOTE that is not a live replica here, a fork that cannot be
    /// uploaded (decided, in a bundle, a value basis, its author erased),
    /// and storage errors.
    pub fn submit_note_fork(&self, id: EntityId, fork: EntityId) -> Result<()> {
        let upload = self.vault.with_write_txn_grouped(|txn| {
            if self.vault.get_entity_type_in_txn(txn, &id)?
                != Some(crate::registry::ENTITY_TYPE_NOTE)
                || !super::DS_E.contains(&self.vault.store, txn, &HexId(id))?
                || self
                    .vault
                    .local_hard_delete_marker_exists_in_txn(txn, &id)?
            {
                return Err(denied());
            }
            // Also refuses soft-erased shells and malformed birth records.
            crate::note::document_birth_in_txn(&self.vault, txn, id)?;
            let upload = crate::note::uploadable_fork_in_txn(&self.vault, txn, id, fork)?
                .ok_or_else(denied)?;
            let input = upload.command_hash()?;
            let key = request_key(id, fork);
            match QN_E.get(&self.vault.store, txn, &key)? {
                Some(previous) => {
                    if PendingNoteRequest::decode(&previous)
                        .ok_or_else(denied)?
                        .input
                        != input
                    {
                        return Err(denied());
                    }
                }
                None => {
                    let marker = encode_document(
                        id,
                        document_sub_tags::NOTE_FORK_UPLOAD,
                        &upload.encode_payload(&[])?,
                    )
                    .into_result()
                    .map_err(|_| denied())?;
                    let pending = PendingNoteRequest {
                        input,
                        frame: &marker,
                    };
                    QN_E.put(&self.vault.store, txn, &key, &pending.encode())?;
                }
            }
            Ok(upload)
        })?;
        let txn = self.vault.store.env.read_txn()?;
        if let Some(frame) = crate::note::fork_upload_frame_in_txn(&self.vault, &txn, id, &upload)?
        {
            let _ = self.notices.send(frame);
        }
        Ok(())
    }

    /// Whether the fork `fork` of the NOTE `id` waits for its authority's
    /// receipt here.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn note_fork_upload_pending(&self, id: EntityId, fork: EntityId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        QN_E.contains(&self.vault.store, &txn, &request_key(id, fork))
    }

    /// Settles the queued upload of the fork `receipt` names on the NOTE
    /// `id`: the receipt must answer that upload's identity as queued. A
    /// receipt for no queued upload changes nothing.
    pub(crate) fn accept_note_fork_receipt(
        &self,
        id: EntityId,
        receipt: &NoteForkUploadReceipt,
    ) -> Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            let key = request_key(id, receipt.fork);
            let Some(stored) = QN_E.get(&self.vault.store, txn, &key)? else {
                return Ok(());
            };
            let pending = PendingNoteRequest::decode(&stored).ok_or_else(denied)?;
            let upload = queued_fork_upload(pending.frame).ok_or_else(denied)??;
            if upload.fork != receipt.fork || upload.command_hash()? != receipt.command_hash {
                return Err(denied());
            }
            QN_E.delete(&self.vault.store, txn, &key)?;
            Ok(())
        })?;
        if let NoteForkUploadOutcome::Refused { reason } = &receipt.outcome {
            tracing::warn!(
                note = %id.to_hex(),
                fork = %receipt.fork.to_hex(),
                %reason,
                "NOTE authority refused a fork upload; the fork stays on this device"
            );
        }
        Ok(())
    }
}

/// `Some` when the queued `frame` is a fork upload's marker: its upload, or
/// the error of a marker that does not read.
pub(super) fn queued_fork_upload(frame: &[u8]) -> Option<Result<NoteForkUpload>> {
    let document = decode_document(frame.get(1..)?).ok()?;
    (document.kind == document_sub_tags::NOTE_FORK_UPLOAD)
        .then(|| NoteForkUpload::decode_payload(document.payload).map(|(upload, _, _)| upload))
}

fn request_key(id: EntityId, fork: EntityId) -> Vec<u8> {
    format!("{}:{}", id.to_hex(), fork.to_hex()).into_bytes()
}

fn denied() -> crate::Error {
    crate::Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}
