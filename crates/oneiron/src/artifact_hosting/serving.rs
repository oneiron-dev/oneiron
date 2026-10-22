//! Read-only resolution of artifact pointers, snapshots, and served files.
//! Resolves immutable code forks and blob versions at their existing read scopes.
//! Pointer writes and the publication lifecycle remain in the parent.

use super::{
    ARTIFACT_POINTERS, ArtifactExportRef, ArtifactFamilyKindId, ArtifactPointer,
    ArtifactPointerChannel, ArtifactPointerRowKey, ArtifactServeTier, ArtifactServedFile,
    ArtifactSnapshotRef, ArtifactSnapshotSelector, CodeArtifactClass, CodebaseForkHash, EntityId,
    EntityStoreRead, Error, Result, Vault, artifact_family_kind_of, decode_code_artifact_body,
    snapshot_file_entry, validate_artifact_id, validate_artifact_path,
};

impl Vault {
    pub fn artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
    ) -> Result<Option<ArtifactPointer>> {
        validate_artifact_id(artifact)?;
        let row = {
            let rtxn = self.store.env.read_txn()?;
            let key = ArtifactPointerRowKey {
                channel,
                artifact: artifact.to_owned(),
            };
            ARTIFACT_POINTERS.get(&self.store, &rtxn, &key)?
        };
        let Some(row) = row else {
            return Ok(None);
        };
        let (export, stale_taint_override, serve_tier) =
            (row.export, row.stale_taint_override, row.serve_tier);
        if self.resolve_export_owner(artifact, export)?.is_none() {
            return Ok(None);
        }
        Ok(Some(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            export,
            stale_taint_override,
            serve_tier,
        }))
    }

    pub fn resolve_artifact_snapshot_by_fork(
        &self,
        artifact: &str,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<ArtifactSnapshotRef>> {
        let rtxn = self.store.env.read_txn()?;
        self.resolve_artifact_snapshot_by_fork_in_txn(&rtxn, artifact, fork_hash)
    }

    /// Transaction-composable body of [`Vault::resolve_artifact_snapshot_by_fork`]:
    /// the first code artifact in fork-index order whose snapshot at
    /// `fork_hash` is `artifact`'s and whose class is `Artifact`, the one
    /// publication of that route selects.
    pub(crate) fn resolve_artifact_snapshot_by_fork_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &str,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<ArtifactSnapshotRef>> {
        validate_artifact_id(artifact)?;
        for code_artifact_id in self.codebase_snapshots_by_fork_hash_in_txn(txn, fork_hash)? {
            let Some(snapshot) = self.get_codebase_snapshot_in_txn(txn, &code_artifact_id)? else {
                continue;
            };
            if snapshot.project_id != artifact {
                continue;
            }
            // This serving adapter mounts code trees only. The semantic family
            // match keeps other registered kinds out without treating their
            // different export bodies as code snapshots.
            let Some(record) = self.store.port_entity_record(txn, &code_artifact_id)? else {
                continue;
            };
            if artifact_family_kind_of(record.entity_type) != Some(ArtifactFamilyKindId::Code) {
                continue;
            }
            if decode_code_artifact_body(&record.body)?.class != CodeArtifactClass::Artifact {
                continue;
            }
            return Ok(Some(ArtifactSnapshotRef {
                artifact: artifact.to_owned(),
                fork_hash: *fork_hash,
                code_artifact_id,
                snapshot,
            }));
        }
        Ok(None)
    }

    pub fn resolve_artifact_file(
        &self,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
    ) -> Result<Option<ArtifactServedFile>> {
        validate_artifact_path(path)?;
        let export = match selector {
            ArtifactSnapshotSelector::Channel(channel) => {
                let Some(pointer) = self.artifact_pointer(artifact, channel)? else {
                    return Ok(None);
                };
                pointer.export
            }
            ArtifactSnapshotSelector::ForkHash(hash) => ArtifactExportRef::ForkHash(hash),
            ArtifactSnapshotSelector::BlobVersion(version) => {
                let Ok(artifact_id) = EntityId::from_hex(artifact) else {
                    return Ok(None);
                };
                ArtifactExportRef::BlobVersion {
                    artifact_id,
                    version,
                }
            }
        };
        match export {
            ArtifactExportRef::ForkHash(fork_hash) => {
                let Some(snapshot_ref) =
                    self.resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
                else {
                    return Ok(None);
                };
                let Some(entry) = snapshot_file_entry(&snapshot_ref.snapshot, path) else {
                    return Ok(None);
                };
                let mount = self
                    .mount_codebase_snapshot(&snapshot_ref.code_artifact_id)?
                    .ok_or(Error::EntityNotFound)?;
                let bytes = mount.read_file(path)?.ok_or(Error::EntityNotFound)?;
                Ok(Some(ArtifactServedFile {
                    artifact: artifact.to_owned(),
                    selector,
                    serve_tier: ArtifactServeTier::Private,
                    export,
                    path: path.to_owned(),
                    media_type: None,
                    content_hash: entry.content_hash,
                    size_bytes: entry.size_bytes,
                    bytes,
                }))
            }
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact != artifact_id.to_hex() || version == 0 {
                    return Ok(None);
                }
                let rtxn = self.store.env.read_txn()?;
                if self
                    .get_blob_artifact_in_txn(&rtxn, &artifact_id)?
                    .is_none()
                {
                    return Ok(None);
                }
                let Some(record) =
                    self.blob_artifact_version_metadata_in_txn(&rtxn, &artifact_id, version)?
                else {
                    return Ok(None);
                };
                // Pin the export presentation with the version. Later body
                // edits cannot rename or retype an already-published route.
                if path != "export" && path != "index.html" && path != record.export_name {
                    return Ok(None);
                }
                let bytes = self
                    .read_blob_artifact_version_in_txn(&rtxn, &artifact_id, version)?
                    .ok_or(Error::EntityNotFound)?;
                if *blake3::hash(&bytes).as_bytes() != record.content_hash {
                    return Err(Error::CorruptedIndex("blob export content hash"));
                }
                let bytes = self.resolve_docx_authors_in_txn(&rtxn, bytes)?; // FIX 4513
                let size_bytes = u64::try_from(bytes.len())
                    .map_err(|_| Error::ArithmeticOverflow("blob export length"))?;
                Ok(Some(ArtifactServedFile {
                    artifact: artifact.to_owned(),
                    selector,
                    serve_tier: ArtifactServeTier::Private,
                    export,
                    path: path.to_owned(),
                    media_type: Some(record.export_media_type),
                    content_hash: record.content_hash,
                    size_bytes,
                    bytes,
                }))
            }
        }
    }
}
