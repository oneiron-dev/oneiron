//! Reading ASSET bodies whatever plane holds them (FIX 3677): a logical
//! reader that streams a body file, checked as it is read, and the
//! materializing readers the whole-body doors keep.

use std::io::Read;

use heed::RoTxn;

use super::{AssetFileManifest, CheckedAssetBody, asset_file_of_raw_in_txn};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;

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
        let body = self.asset_file_body(txn, &manifest)?;
        let mut row = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        row.extend_from_slice(&raw[..ENTITY_METADATA_HEADER_LEN]);
        row.extend_from_slice(&body);
        Ok(row)
    }

    /// [`Self::materialized_row_in_txn`] for a selected revision `raw` of
    /// `id`: the one that is the live row reads as its body; an older one
    /// keeps the manifest it was stored as, whose file a later write may have
    /// released.
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
        if live != Some(true) {
            return Ok(raw);
        }
        self.materialized_row_in_txn(txn, id, raw)
    }

    /// Runs `read` over ASSET `id`'s body as it streams, whichever plane
    /// holds it, under the admission every whole-body read of the row takes
    /// (a withdrawn, stale or unpublished body reads as absent). A body file
    /// is checked against its manifest's length and BLAKE3 as it is read,
    /// and whatever `read` leaves is read too, so the whole body is checked
    /// whether or not `read` reaches its end. `None` when `id` holds no
    /// readable ASSET. The file is pinned while it is read; a reader that
    /// finds `id` in a transaction it opened earlier pins the body first
    /// ([`crate::Vault::pin_all_result_bodies`]).
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
    /// is, as its own door reads it. The caller pins the body before `txn`
    /// opens ([`Self::pin_all_result_bodies`]) and holds the pin while it
    /// reads.
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
