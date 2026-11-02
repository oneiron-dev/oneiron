//! The serving presentation of a published blob version (FIX 1195).
//!
//! A publication carries to the sync server's replica only what serving a
//! blob version reads: the content hash of its bytes and the export name
//! and media type pinned with the version. No provenance, run reference,
//! claim, author or history leaves the device. The replica keeps it as a
//! descriptor keyed by the artifact and its version, which the pointer and
//! the owner bind; the bytes are the content-addressed ASSET window sync
//! delivers. A vault that holds the version itself serves it from the
//! version's own record, and a replica from its descriptor: two current
//! roles, not an old wire. A version record that does not read fails, and
//! never falls back to a descriptor.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{
    ARTIFACT_POINTERS, ArtifactExportRef, ArtifactPointerChannel, ArtifactPointerRow,
    ArtifactPointerRowKey, Vault, validate_artifact_id,
};
use crate::blob_artifact::{
    BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES, BLOB_ARTIFACT_NAME_MAX_BYTES, BlobArtifactVersion,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::SecretSight;
use crate::side_table::{self, Named, SideTable};

/// A replica's descriptor of one published blob version. Key: id16
/// (artifact) + u64be (version).
pub(super) const SERVING_BLOBS: SideTable<(EntityId, u64), ServingBlobDescriptor, Named> =
    SideTable::new(&side_table::ARTIFACT_SERVING_BLOB);

/// What serving one blob version reads, and nothing else: every field is
/// required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServingBlobDescriptor {
    /// The BLAKE3 of the version's bytes, which names their ASSET.
    pub(super) content_hash: [u8; 32],
    /// The export name pinned with the version.
    pub(super) export_name: String,
    /// The export media type pinned with the version.
    pub(super) export_media_type: String,
}

impl ServingBlobDescriptor {
    /// The presentation a version record pins.
    pub(super) fn of_version(record: BlobArtifactVersion) -> Self {
        Self {
            content_hash: record.content_hash,
            export_name: record.export_name,
            export_media_type: record.export_media_type,
        }
    }

    /// Whether its name and media type read as a version record's must:
    /// each non-empty and within its bound.
    pub(super) fn well_formed(&self) -> bool {
        !self.export_name.is_empty()
            && self.export_name.len() <= BLOB_ARTIFACT_NAME_MAX_BYTES
            && !self.export_media_type.is_empty()
            && self.export_media_type.len() <= BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES
    }
}

/// Keeps a replica's descriptor of version `version` of `artifact_id`.
pub(super) fn put_serving_blob_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    artifact_id: &EntityId,
    version: u64,
    serving: &ServingBlobDescriptor,
) -> Result<()> {
    SERVING_BLOBS.put(store, wtxn, &(*artifact_id, version), serving)
}

/// Removes every descriptor of `id`, whatever its version, so an erased
/// blob's presentation never serves under a later chain at the same id.
pub(super) fn remove_serving_blobs_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    SERVING_BLOBS.delete_from(store, wtxn, id.as_bytes())?;
    Ok(())
}

/// Retires, with the producer's exact-version release of version `version`
/// of `id` (FIX 8504), what this vault serves of that version: each channel
/// pointer that names it goes, owed to the sync server as unpublished so the
/// replica's pointer and descriptor go too, and so does this vault's own
/// descriptor of it. Every other version and pointer stays. Never a
/// refusal.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn retire_released_version_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    version: u64,
) -> Result<()> {
    let artifact = id.to_hex();
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        let key = ArtifactPointerRowKey {
            channel,
            artifact: artifact.clone(),
        };
        let row = ARTIFACT_POINTERS.get(store, wtxn, &key)?;
        if names_version(row.as_ref(), id, version) {
            ARTIFACT_POINTERS.delete(store, wtxn, &key)?;
            super::mark_publication_in_txn(store, wtxn, channel, &artifact)?;
        }
    }
    SERVING_BLOBS.delete(store, wtxn, &(*id, version))?;
    Ok(())
}

/// A replica's descriptor of version `version` of `id` goes once no channel
/// pointer here names that version (FIX 8504): an unpublish takes what it
/// served, unless the other channel still serves it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn retire_unpointed_version_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    version: u64,
) -> Result<()> {
    let artifact = id.to_hex();
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        let key = ArtifactPointerRowKey {
            channel,
            artifact: artifact.clone(),
        };
        let row = ARTIFACT_POINTERS.get(store, wtxn, &key)?;
        if names_version(row.as_ref(), id, version) {
            return Ok(());
        }
    }
    SERVING_BLOBS.delete(store, wtxn, &(*id, version))?;
    Ok(())
}

/// Whether `row` points at exactly version `version` of `id`.
fn names_version(row: Option<&ArtifactPointerRow>, id: &EntityId, version: u64) -> bool {
    row.is_some_and(|row| {
        matches!(row.export, ArtifactExportRef::BlobVersion { artifact_id, version: pinned }
            if artifact_id == *id && pinned == version)
    })
}

impl Vault {
    pub(crate) fn resolve_export_owner(
        &self,
        artifact: &str,
        export: ArtifactExportRef,
    ) -> Result<Option<EntityId>> {
        validate_artifact_id(artifact)?;
        match export {
            ArtifactExportRef::ForkHash(fork_hash) => Ok(self
                .resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
                .map(|r| r.code_artifact_id)),
            ArtifactExportRef::BlobVersion { .. } => {
                let rtxn = self.store.env.read_txn()?;
                self.resolve_export_owner_in_txn(&rtxn, artifact, export)
            }
        }
    }

    /// Publish admission runs behind the writer. No concurrent delete may
    /// remove a blob between validating its version and inserting its pointer.
    /// A blob version resolves through its own record or a replica's
    /// descriptor ([`Self::serving_blob_in_txn`]).
    pub(super) fn resolve_export_owner_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact: &str,
        export: ArtifactExportRef,
    ) -> Result<Option<EntityId>> {
        validate_artifact_id(artifact)?;
        match export {
            ArtifactExportRef::ForkHash(_) => self.resolve_export_owner(artifact, export),
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact != artifact_id.to_hex()
                    || version == 0
                    || self.get_blob_artifact_in_txn(rtxn, &artifact_id)?.is_none()
                {
                    return Ok(None);
                }
                Ok(self
                    .serving_blob_in_txn(rtxn, &artifact_id, version)?
                    .map(|_| artifact_id))
            }
        }
    }

    /// What serves version `version` of `artifact_id` here: its own record's
    /// presentation where this vault holds the version (its claim checked),
    /// else a replica's descriptor; `None` when neither is here.
    pub(super) fn serving_blob_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<ServingBlobDescriptor>> {
        if let Some(record) =
            self.blob_artifact_version_metadata_in_txn(rtxn, artifact_id, version)?
        {
            return Ok(Some(ServingBlobDescriptor::of_version(record)));
        }
        SERVING_BLOBS.get(&self.store, rtxn, &(*artifact_id, version))
    }

    /// The bytes `serving` names, for a version of `artifact_id`, as
    /// `sight` reads them, before any DOCX author projection; `None` when
    /// they may not leave (a compaction step's response whose words are
    /// withdrawn). A body kept in its ASSET's file is read through the
    /// checked reader and masked as it passes (FIX 5507, 6507); an inline
    /// one is checked against the descriptor's hash, then masked by its mark.
    pub(super) fn read_serving_blob_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        serving: &ServingBlobDescriptor,
        sight: SecretSight,
    ) -> Result<Option<Vec<u8>>> {
        if !self.blob_artifact_bytes_readable_in_txn(rtxn, artifact_id)? {
            return Ok(None);
        }
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&serving.content_hash)?;
        if let Some(bytes) =
            self.sighted_body_file_in_txn(rtxn, &asset, &serving.content_hash, sight)?
        {
            return Ok(Some(bytes));
        }
        let bytes = crate::ports::BlobStore::port_blob_get(self, rtxn, &serving.content_hash)?
            .ok_or(Error::EntityNotFound)?;
        if blake3::hash(&bytes).as_bytes() != &serving.content_hash {
            return Err(Error::CorruptedIndex("blob export content hash"));
        }
        crate::secret_custody::sighted_bytes_in_txn(
            &self.store,
            rtxn,
            bytes,
            Some(&serving.content_hash),
            sight,
        )
        .map(Some)
    }
}
