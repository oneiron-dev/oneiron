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
}
