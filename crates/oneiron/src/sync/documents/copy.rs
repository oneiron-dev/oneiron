//! A marked repo source's copy stream on the text plane of a device that
//! holds the source (FIX 10872): its subscription and requests go under its
//! copy id, the home's frames under that id land on the source, and each
//! local edit leaves as the copy lineage's operations. The lineage work is
//! [`crate::sync::selector::secret_projection::import_home_copy`]'s and its
//! siblings'; each runs under the source's writer.

use super::{DS_E, DocumentRegistry, EntityDocument, eligible};
use crate::error::{Error, Result};
use crate::side_table::HexId;
use crate::sync::selector::SyncSelector;
use crate::sync::selector::secret_projection::{self as projection, CopyReply, CopyStream};
use crate::sync::transport::{document_sub_tags, encode_document};
use crate::{EntityId, Vault};

impl DocumentRegistry {
    /// The copy stream `id` names on this device, if any.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn copy_stream(&self, id: EntityId) -> Result<Option<CopyStream>> {
        let txn = self.vault.store.env.read_txn()?;
        projection::copy_stream_in_txn(&self.vault, &txn, id)
    }

    /// `stream`'s REQUEST, under its copy id, for the held source.
    pub(super) fn copy_request_frame(
        &self,
        stream: CopyStream,
        selector: &SyncSelector,
    ) -> Result<Vec<u8>> {
        {
            let txn = self.vault.store.env.read_txn()?;
            eligible(&self.vault, &txn, stream.source)?;
        }
        let vv = projection::request_vector(&self.vault, stream)?;
        let payload = crate::sync::selector::encode_selector_vv_request(selector, &vv)?;
        encode_document(stream.wire, document_sub_tags::REQUEST, &payload)
            .into_result()
            .map_err(|_| Error::InvariantViolation("document request exceeds wire limit"))
    }

    /// Moves a subscription stored under a marked source's own id, `bytes`
    /// its selector, to the stream's copy id.
    pub(super) fn move_copy_subscription(&self, stream: CopyStream, bytes: &[u8]) -> Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            DS_E.put(&self.vault.store, txn, &HexId(stream.wire), &bytes.to_vec())?;
            DS_E.delete(&self.vault.store, txn, &HexId(stream.source))?;
            Ok(())
        })
    }

    /// The home's STATE or UPDATE of `stream`, taken on its source under the
    /// source's writer; `admit` judges it in the writer that lands it.
    ///
    /// # Errors
    /// The source's open or eligibility, `admit`'s refusal, or the import's.
    pub(crate) fn copy_import(
        &self,
        stream: CopyStream,
        kind: u8,
        bytes: &[u8],
        admit: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<CopyReply> {
        self.open(stream.source)?
            .import_home_copy(stream, kind, bytes, admit)
    }

    /// The home's ACK of `stream`, under the source's writer.
    ///
    /// # Errors
    /// The source's open, or the acknowledgement's own failure.
    pub(crate) fn copy_acknowledge(&self, stream: CopyStream, remote: &[u8]) -> Result<CopyReply> {
        let document = self.open(stream.source)?;
        let _writer = document.lock()?;
        projection::acknowledge_home_copy(&self.vault, stream, remote)
    }

    /// A local edit's UPDATE payload of `stream`, under the source's writer:
    /// `None` when the home holds the whole lineage or before its basis.
    ///
    /// # Errors
    /// The source's open, or the release's own failure.
    pub(crate) fn copy_release(&self, stream: CopyStream) -> Result<Option<Vec<u8>>> {
        let document = self.open(stream.source)?;
        let _writer = document.lock()?;
        projection::release_device_copy(&self.vault, stream)
    }
}

impl EntityDocument {
    fn import_home_copy(
        &self,
        stream: CopyStream,
        kind: u8,
        bytes: &[u8],
        admit: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<CopyReply> {
        self.refuse_raw_note()?;
        let _writer = self.lock()?;
        projection::import_home_copy(&self.vault, stream, kind, bytes, |txn| {
            eligible(&self.vault, txn, self.id)?;
            admit(txn)
        })
    }
}

/// The marked source a copy stream's wire id `id` stands for here, else
/// `id`: a copy frame is judged as its source (its worlds, its sources).
///
/// # Errors
/// A store failure.
pub(crate) fn judged_id_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<EntityId> {
    Ok(projection::copy_stream_in_txn(vault, txn, id)?
        .filter(|stream| stream.wire == id)
        .map_or(id, |stream| stream.source))
}
