//! The rows one stored version is (FIX 5455): its version CLAIM and the
//! ASSET its bytes are, read beside those bytes, so a door that reads a
//! version it picked itself lists exactly the version it read.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::versions::{BlobArtifactVersion, VERSIONS, blob_artifact_asset_entity_id};

/// The rows `record` is: its version CLAIM and its content's ASSET.
fn blob_version_rows(record: &BlobArtifactVersion) -> Result<Vec<EntityId>> {
    Ok(vec![
        record.claim_id,
        blob_artifact_asset_entity_id(&record.content_hash)?,
    ])
}

/// The rows a family view of `artifact_id`'s version tree `versions` shows
/// (FIX 7645): the artifact, then each version's rows, read from the records
/// alone.
pub(super) fn blob_tree_rows(
    artifact_id: &EntityId,
    versions: &[BlobArtifactVersion],
) -> Result<Vec<EntityId>> {
    let mut rows = Vec::with_capacity(versions.len().saturating_mul(2).saturating_add(1));
    rows.push(*artifact_id);
    for record in versions {
        rows.extend(blob_version_rows(record)?);
    }
    Ok(rows)
}

impl Vault {
    /// [`Vault::read_blob_artifact_version`], beside the rows of the very
    /// record its bytes were read through ([`blob_version_rows`]).
    pub(crate) fn read_blob_artifact_version_listing(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<(Vec<u8>, Vec<EntityId>)>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(record) = VERSIONS.get(&self.store, &rtxn, &(*artifact_id, version))? else {
            return Ok(None);
        };
        let bytes = crate::ports::BlobStore::port_blob_get(self, &rtxn, &record.content_hash)?
            .ok_or(Error::EntityNotFound)?;
        Ok(Some((bytes, blob_version_rows(&record)?)))
    }

    /// The version a read of `artifact_id`'s `version` (the head when `None`)
    /// resolves to, beside its rows ([`blob_version_rows`]), from its
    /// metadata alone with no byte of it read (FIX 7645): what a door admits
    /// before it reads that exact version. `None` when the artifact has no
    /// such version.
    pub fn blob_artifact_version_rows(
        &self,
        artifact_id: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<(u64, Vec<EntityId>)>> {
        let rtxn = self.store.env.read_txn()?;
        let version = match version {
            Some(version) => version,
            None => match super::read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        let Some(record) =
            self.blob_artifact_version_metadata_in_txn(&rtxn, artifact_id, version)?
        else {
            return Ok(None);
        };
        Ok(Some((version, blob_version_rows(&record)?)))
    }
}
