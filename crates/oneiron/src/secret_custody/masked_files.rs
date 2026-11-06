//! The serving doors' reads of files stored with keys in them (OF-560;
//! ARCH-0069 #mask-on-write). The marks, and the copy a masked reader is
//! served, are kept in [`crate::store::file_key_masks`].

use heed::RoTxn;

use crate::blob_artifact::ArtifactExport;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

pub(super) use crate::file_secret_marks::FILLER;
pub(crate) use crate::file_secret_marks::KeySpan;
pub use crate::file_secret_marks::SecretSight;
pub(crate) use crate::file_secret_marks::{KeyPlaces, MemberStep, PlaceHandles};
pub(crate) use crate::file_secret_marks::{filled, filled_with, masked_copy_withheld};
pub(crate) use crate::store::file_key_masks::{
    MASKED_FILE_BAND, MaskedFile, drop_masked_key_in_txn, holds_masked_keys_in_txn,
    masked_file_in_txn, put_masked_file_in_txn, sighted_bytes_in_txn,
};

impl Vault {
    /// `bytes`, read from this vault, as `sight` reads them (see
    /// [`SecretSight`]).
    pub fn sighted_asset_bytes(&self, bytes: Vec<u8>, sight: SecretSight) -> Result<Vec<u8>> {
        let rtxn = self.store.env.read_txn()?;
        sighted_bytes_in_txn(&self.store, &rtxn, bytes, None, sight)
    }

    /// [`Self::sighted_asset_bytes`] for a caller holding `digest`, the
    /// BLAKE3 of `bytes` computed from, or checked against, these exact
    /// bytes: the mark is read by it and the bytes are not hashed again
    /// (speed).
    pub(crate) fn sighted_asset_bytes_with_digest(
        &self,
        bytes: Vec<u8>,
        digest: &[u8; 32],
        sight: SecretSight,
    ) -> Result<Vec<u8>> {
        let rtxn = self.store.env.read_txn()?;
        sighted_bytes_in_txn(&self.store, &rtxn, bytes, Some(digest), sight)
    }

    /// [`Vault::export_blob_artifact`] for a reader at a serving door. The
    /// export's `content_hash` still names the stored version.
    pub fn export_blob_artifact_as(
        &self,
        id: &EntityId,
        version: Option<u64>,
        sight: SecretSight,
    ) -> Result<Option<ArtifactExport>> {
        let Some(mut file) = self.export_blob_artifact_as_raw(id, version, sight)? else {
            return Ok(None);
        };
        // FIX 4513: once, after custody read the stored bytes.
        file.bytes = self.resolve_docx_authors(std::mem::take(&mut file.bytes))?;
        Ok(Some(file))
    }

    /// [`Vault::export_blob_artifact_as`] with a DOCX's default-author token
    /// kept, for a door that reads the file's units and hands no file out. A
    /// version whose body is its ASSET's file is masked as it is read, never
    /// held whole beside its copy (FIX 6507).
    pub(crate) fn export_blob_artifact_as_raw(
        &self,
        id: &EntityId,
        version: Option<u64>,
        sight: SecretSight,
    ) -> Result<Option<ArtifactExport>> {
        let txn = self.store.env.read_txn()?;
        self.export_blob_artifact_read_in_txn(&txn, id, version, |record| {
            self.read_blob_artifact_version_sighted_in_txn(&txn, id, record.version, sight)?
                .ok_or(Error::EntityNotFound)
        })
    }

    /// [`Vault::read_blob_artifact_version`] for a reader at a serving door.
    /// A version whose body is its ASSET's file is read from the file as
    /// `sight` reads it (FIX 5507, `sighted_file`).
    pub fn read_blob_artifact_version_as(
        &self,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.read_blob_artifact_version_sighted_in_txn(&rtxn, artifact_id, version, sight)?
            // FIX 4513: once, after custody read the stored bytes.
            .map(|bytes| self.resolve_docx_authors_in_txn(&rtxn, bytes))
            .transpose()
    }

    /// The version an export of `artifact`'s `version` (the head when
    /// `None`) reads, with its stored digest, when that version's body is
    /// kept in its ASSET's file and a mark covers the file (FIX 6507): the
    /// stored bytes are verified through the checked reader and dropped as
    /// they pass, before any receipt is written. `None` for any other
    /// version, and for one whose bytes may not leave.
    pub(crate) fn marked_blob_version_file(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<(u64, [u8; 32])>> {
        let txn = self.store.env.read_txn()?;
        let version = match version {
            Some(version) => version,
            None => match crate::blob_artifact::read_blob_artifact_head_in_txn(
                &self.store,
                &txn,
                artifact,
            )? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        if self
            .blob_artifact_version_metadata_in_txn(&txn, artifact, version)?
            .is_none()
        {
            return Ok(None);
        }
        let Some((asset, hash)) =
            self.blob_artifact_version_file_in_txn(&txn, artifact, version)?
        else {
            return Ok(None);
        };
        if masked_file_in_txn(&self.store, &txn, &hash)?.is_none()
            || !self.check_body_file_in_txn(&txn, &asset, &hash)?
        {
            return Ok(None);
        }
        Ok(Some((version, hash)))
    }

    /// One version's bytes as `sight` reads them in `txn`, before any DOCX
    /// author projection. A body kept in its ASSET's file is read through
    /// the checked reader and masked as it passes ([`Self::sighted_body_file_in_txn`],
    /// FIX 5507, 6507); any other body is read whole, checked, and masked by
    /// its mark. `None` when the version's bytes may not leave.
    pub(crate) fn read_blob_artifact_version_sighted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        if let Some((asset, hash)) =
            self.blob_artifact_version_file_in_txn(txn, artifact_id, version)?
        {
            return self
                .sighted_body_file_in_txn(txn, &asset, &hash, sight)?
                .ok_or(Error::EntityNotFound)
                .map(Some);
        }
        self.read_blob_artifact_version_in_txn(txn, artifact_id, version)?
            .map(|bytes| sighted_bytes_in_txn(&self.store, txn, bytes, None, sight))
            .transpose()
    }
}
