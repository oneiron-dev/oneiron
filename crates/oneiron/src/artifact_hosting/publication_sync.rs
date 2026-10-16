//! Publication sync: a pinned channel pointer, with the rows that make its
//! export servable, reaches the sync server's replica of this vault.
//!
//! The bytes are content-addressed ASSET rows, and the owner and claim
//! entities are ordinary rows; window sync already carries all of them,
//! through its own admission. This lane carries what a window does not: the
//! pointer row, the code snapshot manifest or the blob version record. The
//! receiver applies a publication only once every row it names is present
//! and every byte hashes to its name, so a served file is the pinned file.
//! Until then it answers `Staged`, and the device sends it again.

use super::*;
use crate::sync::transport::{document_sub_tags, encode_document};

/// Empty marker per changed channel pointer; cleared by a matching receipt.
const PUBLICATION_OUTBOX: SideTable<ArtifactPointerRowKey, (), Raw> =
    SideTable::new(&side_table::ARTIFACT_SYNC_OUTBOX);

const PUBLICATION_ID_DOMAIN: &[u8] = b"oneiron.artifact.publication.v1";
const RECEIPT_LEN: usize = 33;

/// What the sync server did with one publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactPublicationOutcome {
    /// The pointer serves (or, for an unpublish, no longer serves) there.
    Applied,
    /// A row it names has not arrived by window sync yet; send it again.
    Staged,
    /// Malformed or inconsistent; sending it again would change nothing.
    Refused,
}

impl ArtifactPublicationOutcome {
    const fn byte(self) -> u8 {
        match self {
            Self::Applied => 0,
            Self::Staged => 1,
            Self::Refused => 2,
        }
    }

    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Applied),
            1 => Some(Self::Staged),
            2 => Some(Self::Refused),
            _ => None,
        }
    }
}

/// One frame the device owes the sync server, with the digest its receipt names.
#[derive(Debug, Clone)]
pub struct ArtifactPublicationFrame {
    pub digest: [u8; 32],
    pub frame: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicationWire {
    channel: u8,
    artifact: String,
    /// `None`: the channel serves nothing now.
    published: Option<PublishedWire>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublishedWire {
    /// The pointer row's stored bytes: export, stale stamp and serve tier
    /// (a link tier holds only its token's digest).
    pointer: Vec<u8>,
    owner: EntityId,
    rows: ExportWire,
}

#[derive(Debug, Serialize, Deserialize)]
enum ExportWire {
    /// The encoded snapshot manifest the fork hash names.
    Code { snapshot: Vec<u8> },
    /// The blob version record's stored bytes.
    Blob { version: Vec<u8> },
}

/// Marks a channel pointer as owed to the sync server, in the transaction that changes it.
pub(super) fn mark_publication_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    channel: ArtifactPointerChannel,
    artifact: &str,
) -> Result<()> {
    PUBLICATION_OUTBOX.put(
        store,
        wtxn,
        &ArtifactPointerRowKey {
            channel,
            artifact: artifact.to_owned(),
        },
        &(),
    )
}

fn publication_entity_id(channel: ArtifactPointerChannel, artifact: &str) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        PUBLICATION_ID_DOMAIN,
        &[&[channel.key_byte()], artifact.as_bytes()],
    )
}

fn receipt_frame(
    entity: EntityId,
    digest: [u8; 32],
    outcome: ArtifactPublicationOutcome,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(RECEIPT_LEN);
    payload.extend_from_slice(&digest);
    payload.push(outcome.byte());
    encode_document(entity, document_sub_tags::ARTIFACT_RECEIPT, &payload)
        .into_result()
        .map_err(|_| Error::InvariantViolation("artifact receipt exceeds wire limit"))
}

fn denied() -> Error {
    Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}

impl Vault {
    /// Every publication this device still owes the sync server, each as it
    /// stands now: a pointer changed twice is sent once, in its last state.
    pub fn artifact_publication_frames(&self) -> Result<Vec<ArtifactPublicationFrame>> {
        let txn = self.store.env.read_txn()?;
        let mut frames = Vec::new();
        for (key, ()) in PUBLICATION_OUTBOX.scan(&self.store, &txn)? {
            let payload = self.publication_payload_in_txn(&txn, &key)?;
            let frame = encode_document(
                publication_entity_id(key.channel, &key.artifact)?,
                document_sub_tags::ARTIFACT_PUBLICATION,
                &payload,
            )
            .into_result()
            .map_err(|_| Error::InvariantViolation("artifact publication exceeds wire limit"))?;
            frames.push(ArtifactPublicationFrame {
                digest: *blake3::hash(&payload).as_bytes(),
                frame,
            });
        }
        Ok(frames)
    }

    /// Clears the outbox row a receipt answers, unless the pointer changed
    /// after that frame left: its newer state is still owed.
    pub fn accept_artifact_publication_receipt(
        &self,
        entity: EntityId,
        payload: &[u8],
    ) -> Result<ArtifactPublicationOutcome> {
        let (digest, outcome) = match payload {
            [digest @ .., outcome] if payload.len() == RECEIPT_LEN => (
                <[u8; 32]>::try_from(digest).map_err(|_| denied())?,
                ArtifactPublicationOutcome::from_byte(*outcome).ok_or_else(denied)?,
            ),
            _ => return Err(denied()),
        };
        if outcome == ArtifactPublicationOutcome::Staged {
            return Ok(outcome);
        }
        let mut wtxn = self.store.env.write_txn()?;
        for (key, ()) in PUBLICATION_OUTBOX.scan(&self.store, &wtxn)? {
            if publication_entity_id(key.channel, &key.artifact)? != entity {
                continue;
            }
            let current = self.publication_payload_in_txn(&wtxn, &key)?;
            if *blake3::hash(&current).as_bytes() == digest {
                PUBLICATION_OUTBOX.delete(&self.store, &mut wtxn, &key)?;
            }
        }
        wtxn.commit()?;
        Ok(outcome)
    }

    fn publication_payload_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &ArtifactPointerRowKey,
    ) -> Result<Vec<u8>> {
        let published = match ARTIFACT_POINTERS.get(&self.store, txn, key)? {
            Some(row) => self.published_wire_in_txn(txn, &key.artifact, &row)?,
            None => None,
        };
        let wire = PublicationWire {
            channel: key.channel.key_byte(),
            artifact: key.artifact.clone(),
            published,
        };
        rmp_serde::to_vec_named(&wire)
            .map_err(|_| Error::InvariantViolation("artifact publication encode"))
    }

    /// The rows a live pointer serves from. A pointer whose export no longer
    /// resolves here serves nothing here, so it is sent as unpublished.
    fn published_wire_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &str,
        row: &ArtifactPointerRow,
    ) -> Result<Option<PublishedWire>> {
        let pointer = ARTIFACT_POINTERS.encode_value(row)?;
        Ok(match row.export {
            ArtifactExportRef::ForkHash(hash) => self
                .resolve_artifact_snapshot_by_fork_in_txn(txn, artifact, &hash)?
                .map(|found| -> Result<PublishedWire> {
                    Ok(PublishedWire {
                        pointer,
                        owner: found.code_artifact_id,
                        rows: ExportWire::Code {
                            snapshot: crate::codebase::encode_codebase_snapshot(&found.snapshot)?,
                        },
                    })
                })
                .transpose()?,
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => self
                .blob_artifact_version_record_bytes_in_txn(txn, &artifact_id, version)?
                .map(|version| PublishedWire {
                    pointer,
                    owner: artifact_id,
                    rows: ExportWire::Blob { version },
                }),
        })
    }

    /// The sync server's door for one publication frame from the owner's
    /// device. Returns the receipt frame for that socket. A malformed or
    /// inconsistent publication is `Refused`, never a socket error; only a
    /// storage failure is an error.
    pub fn import_artifact_publication(&self, entity: EntityId, payload: &[u8]) -> Result<Vec<u8>> {
        let digest = *blake3::hash(payload).as_bytes();
        let outcome = self.apply_artifact_publication(entity, payload)?;
        receipt_frame(entity, digest, outcome)
    }

    fn apply_artifact_publication(
        &self,
        entity: EntityId,
        payload: &[u8],
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::{Applied, Refused};
        let Ok(wire) = rmp_serde::from_slice::<PublicationWire>(payload) else {
            return Ok(Refused);
        };
        let Some(channel) = ArtifactPointerChannel::from_key_byte(wire.channel) else {
            return Ok(Refused);
        };
        if validate_artifact_id(&wire.artifact).is_err()
            || publication_entity_id(channel, &wire.artifact)? != entity
        {
            return Ok(Refused);
        }
        let key = ArtifactPointerRowKey {
            channel,
            artifact: wire.artifact.clone(),
        };
        let Some(published) = wire.published else {
            let mut wtxn = self.store.env.write_txn()?;
            ARTIFACT_POINTERS.delete(&self.store, &mut wtxn, &key)?;
            wtxn.commit()?;
            return Ok(Applied);
        };
        let Ok(pointer) = ARTIFACT_POINTERS.decode_value(&published.pointer) else {
            return Ok(Refused);
        };
        // Dropping the transaction unapplied aborts every row written below.
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = match (pointer.export, published.rows) {
            (ArtifactExportRef::ForkHash(hash), ExportWire::Code { snapshot }) => {
                let Ok(snapshot) = crate::codebase::decode_codebase_snapshot(&snapshot) else {
                    return Ok(Refused);
                };
                // The fork hash is recomputed from the manifest, never taken on trust.
                let Ok(rebuilt) = CodebaseSnapshot::new(
                    snapshot.project_id.clone(),
                    snapshot.repo_ref.clone(),
                    snapshot.commit_hash.clone(),
                    snapshot.files.clone(),
                ) else {
                    return Ok(Refused);
                };
                if rebuilt.fork_hash != hash
                    || snapshot.fork_hash != hash
                    || snapshot.project_id != wire.artifact
                {
                    return Ok(Refused);
                }
                self.stage_code_rows_in_txn(&mut wtxn, &published.owner, &rebuilt)?
            }
            (
                ArtifactExportRef::BlobVersion {
                    artifact_id,
                    version,
                },
                ExportWire::Blob { version: record },
            ) => {
                if artifact_id != published.owner || wire.artifact != artifact_id.to_hex() {
                    return Ok(Refused);
                }
                self.stage_blob_rows_in_txn(&mut wtxn, &artifact_id, version, &record)?
            }
            _ => return Ok(Refused),
        };
        if outcome != Applied {
            return Ok(outcome);
        }
        ARTIFACT_POINTERS.put(&self.store, &mut wtxn, &key, &pointer)?;
        wtxn.commit()?;
        Ok(Applied)
    }

    /// The manifest of a hostable code artifact whose owner row and every
    /// file's bytes window sync has already delivered.
    fn stage_code_rows_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        owner: &EntityId,
        snapshot: &CodebaseSnapshot,
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::{Applied, Staged};
        let Some(record) = self.store.port_entity_record(wtxn, owner)? else {
            return Ok(Staged);
        };
        if record.entity_type != crate::registry::ENTITY_TYPE_CODE_ARTIFACT {
            return Ok(Staged);
        }
        let Ok(body) = decode_code_artifact_body(&record.body) else {
            return Ok(Staged);
        };
        if body.class != CodeArtifactClass::Artifact
            || crate::codebase::RepoRef::parse(&body.repo_ref)
                .ok()
                .as_ref()
                != Some(&snapshot.repo_ref)
        {
            return Ok(Staged);
        }
        for file in &snapshot.files {
            // Checks the ASSET is there and hashes to the manifest's name.
            if crate::codebase::read_asset_blob_in_txn(self, wtxn, &file.content_hash).is_err() {
                return Ok(Staged);
            }
        }
        self.put_filtered_codebase_snapshot_in_txn(
            wtxn,
            owner,
            snapshot,
            crate::secret_snapshot::SnapshotCustodyReport::default(),
        )?;
        Ok(Applied)
    }

    /// The version record of a blob whose artifact row, `blob.version` claim
    /// and bytes window sync has already delivered.
    fn stage_blob_rows_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
        record: &[u8],
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::{Applied, Refused, Staged};
        if !matches!(
            self.get_blob_artifact_in_txn(wtxn, artifact_id),
            Ok(Some(_))
        ) {
            return Ok(Staged);
        }
        let Ok(written) = self.put_synced_blob_artifact_version_in_txn(wtxn, artifact_id, record)
        else {
            return Ok(Refused);
        };
        if written.version != version {
            return Ok(Refused);
        }
        // The record must agree with its replicated claim, as the reader checks.
        if !matches!(
            self.blob_artifact_version_metadata_in_txn(wtxn, artifact_id, version),
            Ok(Some(_))
        ) {
            return Ok(Staged);
        }
        match self.read_blob_artifact_version_in_txn(wtxn, artifact_id, version) {
            Ok(Some(bytes)) if *blake3::hash(&bytes).as_bytes() == written.content_hash => {
                Ok(Applied)
            }
            _ => Ok(Staged),
        }
    }
}
