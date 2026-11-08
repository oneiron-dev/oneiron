//! Reading ASSET bodies whatever plane holds them (FIX 3677): a logical
//! reader that streams a body file, checked as it is read, and the
//! materializing readers the whole-body doors keep.

use std::borrow::Cow;
use std::io::Read;

use heed::RoTxn;

use super::{
    AssetFileKind, AssetFileManifest, CheckedAssetBody, asset_file_in_txn,
    asset_file_of_raw_in_txn, revision_file_in_txn,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::store::Store;

/// The bytes an owning adapter reads in ASSET `id`'s stored body `body`
/// (its row after the metadata header), whichever plane holds them (FIX
/// 22091): an inline body as it is, whatever its bytes; a carrier's body
/// file ([`AssetFileKind::Carrier`]) read whole and checked against its
/// manifest's length and BLAKE3, through the key row `txn` names. Any other
/// body file comes back as its stored manifest, which no adapter's decoder
/// takes for a carrier: a reader that walks every ASSET reads no file that
/// holds none. This is storage, not a read grant: the caller has admitted
/// the row.
///
/// The caller holds what a file read needs: a writer, whose snapshot keeps
/// the file, or a read transaction, whose snapshot keeps it too: the
/// collector unlinks no file a live read snapshot names (FIX 22101). The
/// custody guard holds where the caller holds none already.
///
/// # Errors
///
/// [`crate::error::Error::CorruptedIndex`] when the row's descriptor and
/// manifest disagree; a missing file, one whose bytes disagree with its
/// manifest, and storage and filesystem errors.
pub(crate) fn asset_carrier_body_in_txn<'b>(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    body: &'b [u8],
) -> Result<Cow<'b, [u8]>> {
    let Some(manifest) = asset_file_in_txn(store, txn, id, body)?
        .filter(|manifest| manifest.kind == AssetFileKind::Carrier)
    else {
        return Ok(Cow::Borrowed(body));
    };
    let key = crate::store::body_key_row_in_txn(store, txn, &manifest.facts.blake3)?;
    CheckedAssetBody::read_all(&store.body_dir()?, &manifest.facts, key.as_ref()).map(Cow::Owned)
}

impl crate::Vault {
    /// The whole body `manifest` names, read from its file and checked, as
    /// its key row in `txn`, the snapshot that found the manifest, names it
    /// (FIX 5348).
    ///
    /// # Errors
    ///
    /// A missing file, one whose bytes disagree with the manifest, and
    /// filesystem errors.
    pub(crate) fn asset_file_body(
        &self,
        txn: &RoTxn<'_>,
        manifest: &AssetFileManifest,
    ) -> Result<Vec<u8>> {
        let _pin = self.pin_result_body(manifest.facts.blake3);
        let key = crate::store::body_key_row_in_txn(&self.store, txn, &manifest.facts.blake3)?;
        CheckedAssetBody::read_all(&self.store.body_dir()?, &manifest.facts, key.as_ref())
    }

    /// `raw`, a stored row `id` read through a raw port, with a file-plane
    /// ASSET's body in place of its manifest: the row a whole-body reader
    /// was handed before the file plane. Any other row comes back as it is.
    ///
    /// # Errors
    ///
    /// [`Self::asset_file_body`]'s errors, and storage errors.
    pub(crate) fn materialized_row_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        raw: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let Some(manifest) = asset_file_of_raw_in_txn(&self.store, txn, id, &raw)? else {
            return Ok(raw);
        };
        self.row_with_file_body_in_txn(txn, &manifest, &raw)
    }

    /// `raw`'s metadata header followed by the whole body `manifest` names.
    fn row_with_file_body_in_txn(
        &self,
        txn: &RoTxn<'_>,
        manifest: &AssetFileManifest,
        raw: &[u8],
    ) -> Result<Vec<u8>> {
        let body = self.asset_file_body(txn, manifest)?;
        let mut row = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        row.extend_from_slice(&raw[..ENTITY_METADATA_HEADER_LEN]);
        row.extend_from_slice(&body);
        Ok(row)
    }

    /// [`Self::materialized_row_in_txn`] for a selected revision `raw` of
    /// `id`: the one that is the live row reads as its body; an older one
    /// reads as the body of the file its manifest names while one of `id`'s
    /// descriptors holds it ([`revision_file_in_txn`]): its revisions keep a
    /// file a later write superseded (FIX 22091). Another keeps the manifest
    /// it was stored as.
    ///
    /// # Errors
    ///
    /// [`Self::materialized_row_in_txn`]'s errors.
    pub(crate) fn materialized_revision_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        raw: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let live = self
            .store
            .port_entity_with_raw(txn, id, |live| Ok(live == raw.as_slice()))?;
        if live == Some(true) {
            return self.materialized_row_in_txn(txn, id, raw);
        }
        match revision_file_in_txn(&self.store, txn, id, &raw)? {
            Some(manifest) => self.row_with_file_body_in_txn(txn, &manifest, &raw),
            None => Ok(raw),
        }
    }

    /// Runs `read` over ASSET `id`'s body as it streams, whichever plane
    /// holds it, under the admission every whole-body read of the row takes
    /// (a withdrawn, stale or unpublished body reads as absent). A body file
    /// is checked against its manifest's length and BLAKE3 as it is read,
    /// and whatever `read` leaves is read too, so the whole body is checked
    /// whether or not `read` reaches its end. `None` when `id` holds no
    /// readable ASSET. The file is pinned while it is read; `txn`'s own
    /// snapshot keeps the file it names until it ends (FIX 22101).
    ///
    /// # Errors
    ///
    /// `read`'s error, the check's, and storage and filesystem errors.
    pub(crate) fn with_asset_body_reader_in_txn<T>(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(row) = self.store.port_entity_record(txn, id)? else {
            return Ok(None);
        };
        if row.entity_type != ENTITY_TYPE_ASSET {
            return Ok(None);
        }
        let Some(manifest) = super::asset_file_in_txn(&self.store, txn, id, &row.body)? else {
            let Some(row) = self.live_entity_in_txn(&self.store, txn, id)? else {
                return Ok(None);
            };
            return read(&mut row.body.as_slice()).map(Some);
        };
        if crate::origin::lfs::unpublished_lfs_chunk_in_txn(&self.store, txn, id, row.entity_type)?
            || !crate::ports::body_readable_in_txn(
                &self.store,
                txn,
                id,
                &row.body,
                crate::ports::BodyStale::Withdrawn,
            )?
        {
            return Ok(None);
        }
        let _pin = self.pin_result_body(manifest.facts.blake3);
        let key = crate::store::body_key_row_in_txn(&self.store, txn, &manifest.facts.blake3)?;
        let mut body =
            CheckedAssetBody::open(&self.store.body_dir()?, &manifest.facts, key.as_ref())?;
        let value = read(&mut body)?;
        body.finish()?;
        Ok(Some(value))
    }

    /// The body file `manifest` names, open to stream and checked against
    /// the manifest's length and BLAKE3 as its end is read, as its key row
    /// in `txn`, the snapshot that found the manifest, names it (FIX 3677).
    /// It judges no admission: the caller has admitted the row the manifest
    /// is, as its own door reads it. `txn`'s snapshot keeps the file it
    /// names while `txn` is live (FIX 22101); a caller that reads past
    /// `txn` pins the body ([`Self::pin_result_body`]) before it ends.
    ///
    /// # Errors
    ///
    /// A missing file, and storage and filesystem errors.
    pub(crate) fn admitted_asset_file_in_txn(
        &self,
        txn: &RoTxn<'_>,
        manifest: &AssetFileManifest,
    ) -> Result<CheckedAssetBody> {
        let key = crate::store::body_key_row_in_txn(&self.store, txn, &manifest.facts.blake3)?;
        CheckedAssetBody::open(&self.store.body_dir()?, &manifest.facts, key.as_ref())
    }

    /// Runs `read` over [`Self::admitted_asset_file_in_txn`]'s file, pinned
    /// while it is read. Whatever `read` leaves is read too, so the whole
    /// body is checked whether or not `read` reaches its end, and a failed
    /// check is the error before `read`'s own.
    ///
    /// # Errors
    ///
    /// The check's error, then `read`'s, and storage and filesystem errors.
    pub(crate) fn with_admitted_asset_file_in_txn<T>(
        &self,
        txn: &RoTxn<'_>,
        manifest: &AssetFileManifest,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<T> {
        let _pin = self.pin_result_body(manifest.facts.blake3);
        let mut body = self.admitted_asset_file_in_txn(txn, manifest)?;
        let value = read(&mut body);
        body.finish()?;
        value
    }
}
