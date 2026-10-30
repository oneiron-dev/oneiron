//! Publication sync: a pinned channel pointer, with the rows that make its
//! export servable, reaches the sync server's replica of this vault.
//!
//! The bytes are content-addressed ASSET rows, and the owner and claim
//! entities are ordinary rows; window sync already carries all of them,
//! through its own admission. This lane carries what a window does not: the
//! pointer row, and the code snapshot manifest or the blob version's serving
//! descriptor (FIX 1195): its content hash, export name and media type, and
//! nothing of its provenance, run, claim or history. Each publication names
//! the pointer change it carries, and goes in bounded parts (`parts`, FIX
//! 9575). The receiver applies a publication only once every part is there,
//! the whole hashes to the digest each part names, every row it names is
//! present and every byte hashes to its name, so a served file is the pinned
//! file. Until then it answers `Staged`, and the device sends it again.

use super::serving_blob::{
    ServingBlobDescriptor, put_serving_blob_in_txn, retire_unpointed_version_in_txn,
};
use super::*;
use crate::side_table::Named;

// Bounded parts, their spool and the complete receipt (FIX 9575).
mod parts;
pub(crate) use self::parts::{
    ArtifactPublicationCursor, ArtifactPublicationPart, ArtifactPublicationStep,
};

/// One marker per changed channel pointer, naming that change; cleared by a
/// receipt for the publication of that change as it stands.
const PUBLICATION_OUTBOX: SideTable<ArtifactPointerRowKey, PublicationOutboxMarker, Named> =
    SideTable::new(&side_table::ARTIFACT_SYNC_OUTBOX);

const PUBLICATION_ID_DOMAIN: &[u8] = b"oneiron.artifact.publication.v1";
const RECEIPT_LEN: usize = 33;

/// The change a pointer's outbox marker names: 16 random bytes, fresh for
/// each change of the pointer, an unpublish included, and kept across that
/// change's retries. An opaque transfer identity, never a version or an
/// order between devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationOutboxMarker {
    change_id: [u8; 16],
}

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationWire {
    /// The pointer change this publication carries.
    change_id: [u8; 16],
    channel: u8,
    artifact: String,
    /// `None`: the channel serves nothing now.
    published: Option<PublishedWire>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// What serving the blob version reads, never its version record.
    Blob { serving: ServingBlobDescriptor },
}

/// Marks a channel pointer as owed to the sync server, under a new change, in
/// the transaction that changes it.
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
        &PublicationOutboxMarker {
            change_id: parts::new_publication_change_id(),
        },
    )
}

fn publication_entity_id(channel: ArtifactPointerChannel, artifact: &str) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        PUBLICATION_ID_DOMAIN,
        &[&[channel.key_byte()], artifact.as_bytes()],
    )
}

/// Writes `wire`'s serialization to `out`: the bytes every part carries and
/// the complete digest names.
fn write_publication(out: &mut impl std::io::Write, wire: &PublicationWire) -> Result<()> {
    rmp_serde::encode::write_named(out, wire)
        .map_err(|_| Error::InvariantViolation("artifact publication encode"))
}

fn denied() -> Error {
    Error::sync_protocol(crate::error::SyncProtocolValidation::DocumentAdmissionDenied)
}

/// An outbox row that reads as a marker, or `None` for one that does not
/// decode as one: no publication this lane carries, left as it is. A storage
/// failure stays an error.
fn readable_marker(
    row: Result<(ArtifactPointerRowKey, PublicationOutboxMarker)>,
) -> Result<Option<(ArtifactPointerRowKey, PublicationOutboxMarker)>> {
    match row {
        Ok(row) => Ok(Some(row)),
        Err(Error::Store(crate::error::StoreError::SideTableRow { .. })) => Ok(None),
        Err(error) => Err(error),
    }
}

impl Vault {
    /// Clears the outbox row a complete receipt answers, and its spool,
    /// unless the pointer changed after that publication left: its newer
    /// state is still owed. A receipt names the whole publication, never a
    /// part.
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
        let mut settled = Vec::new();
        for row in PUBLICATION_OUTBOX.iter_from(&self.store, &wtxn, &[])? {
            let Some((key, marker)) = readable_marker(row)? else {
                continue;
            };
            if publication_entity_id(key.channel, &key.artifact)? == entity
                && self.publication_digest_in_txn(&wtxn, &key, marker.change_id)? == digest
            {
                settled.push(key);
            }
        }
        for key in &settled {
            PUBLICATION_OUTBOX.delete(&self.store, &mut wtxn, key)?;
            parts::drop_sent_in_txn(&self.store, &mut wtxn, &entity)?;
        }
        wtxn.commit()?;
        Ok(outcome)
    }

    /// The publication `key` owes for change `change_id`, as it stands now.
    fn publication_wire_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &ArtifactPointerRowKey,
        change_id: [u8; 16],
    ) -> Result<PublicationWire> {
        let published = match ARTIFACT_POINTERS.get(&self.store, txn, key)? {
            Some(row) => self.published_wire_in_txn(txn, &key.artifact, &row)?,
            None => None,
        };
        Ok(PublicationWire {
            change_id,
            channel: key.channel.key_byte(),
            artifact: key.artifact.clone(),
            published,
        })
    }

    /// The BLAKE3 of that publication's serialization, hashed as it is
    /// made: no copy of it is held.
    fn publication_digest_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &ArtifactPointerRowKey,
        change_id: [u8; 16],
    ) -> Result<[u8; 32]> {
        let wire = self.publication_wire_in_txn(txn, key, change_id)?;
        let mut hasher = blake3::Hasher::new();
        write_publication(&mut hasher, &wire)?;
        Ok(*hasher.finalize().as_bytes())
    }

    /// The rows a live pointer serves from. A pointer whose export no longer
    /// resolves here serves nothing here, so it is sent as unpublished. A
    /// blob version is projected from its own record, its claim checked:
    /// only the serving descriptor leaves.
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
                .blob_artifact_version_metadata_in_txn(txn, &artifact_id, version)?
                .map(|record| PublishedWire {
                    pointer,
                    owner: artifact_id,
                    rows: ExportWire::Blob {
                        serving: ServingBlobDescriptor::of_version(record),
                    },
                }),
        })
    }

    /// The sync server's door for one publication part from the owner's
    /// device. Returns the receipt frame for that socket, only once the
    /// publication the part completes is applied, staged or refused; a part
    /// that leaves it incomplete has none. `live` rechecks the caller's
    /// credential inside every writer that keeps a part or applies the
    /// publication. A malformed or inconsistent publication is `Refused`,
    /// never a socket error; a credential no longer live is refused
    /// admission, and a storage failure is an error.
    pub fn import_artifact_publication(
        &self,
        entity: EntityId,
        payload: &[u8],
        live: impl Fn(&RwTxn<'_>) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        self.import_publication_part(entity, payload, &live)
    }

    /// Applies one complete publication in `wtxn`. Its rows and pointer are
    /// written only for `Applied`, which the caller alone commits; a
    /// malformed or inconsistent one is `Refused`, and one whose rows window
    /// sync has not delivered yet `Staged`, each with nothing written.
    fn apply_publication_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entity: EntityId,
        wire: PublicationWire,
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::{Applied, Refused};
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
            // What the pointer served goes with it, unless the other channel
            // still serves it (FIX 8504).
            let unpointed = ARTIFACT_POINTERS.get(&self.store, wtxn, &key)?;
            ARTIFACT_POINTERS.delete(&self.store, wtxn, &key)?;
            if let Some(ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            }) = unpointed.map(|row| row.export)
            {
                retire_unpointed_version_in_txn(&self.store, wtxn, &artifact_id, version)?;
            }
            return Ok(Applied);
        };
        let Ok(pointer) = ARTIFACT_POINTERS.decode_value(&published.pointer) else {
            return Ok(Refused);
        };
        let outcome = match (pointer.export, published.rows) {
            (ArtifactExportRef::ForkHash(hash), ExportWire::Code { snapshot }) => self
                .stage_code_publication_in_txn(
                    wtxn,
                    &wire.artifact,
                    hash,
                    &published.owner,
                    &snapshot,
                )?,
            (
                ArtifactExportRef::BlobVersion {
                    artifact_id,
                    version,
                },
                ExportWire::Blob { serving },
            ) => {
                if artifact_id != published.owner || wire.artifact != artifact_id.to_hex() {
                    return Ok(Refused);
                }
                self.stage_serving_blob_in_txn(wtxn, &artifact_id, version, &serving)?
            }
            _ => return Ok(Refused),
        };
        if outcome == Applied {
            ARTIFACT_POINTERS.put(&self.store, wtxn, &key, &pointer)?;
        }
        Ok(outcome)
    }

    /// A code publication's manifest, checked against the fork hash it is
    /// published at and staged.
    fn stage_code_publication_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &str,
        hash: CodebaseForkHash,
        owner: &EntityId,
        snapshot: &[u8],
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::Refused;
        let Ok(snapshot) = crate::codebase::decode_codebase_snapshot(snapshot) else {
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
            || snapshot.project_id != artifact
        {
            return Ok(Refused);
        }
        self.stage_code_rows_in_txn(wtxn, owner, &rebuilt)
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

    /// A blob version's serving descriptor, kept once the blob's row and
    /// the bytes it names have arrived by window sync and the bytes hash to
    /// that name. No version record is written and no claim is waited on.
    fn stage_serving_blob_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
        serving: &ServingBlobDescriptor,
    ) -> Result<ArtifactPublicationOutcome> {
        use ArtifactPublicationOutcome::{Applied, Refused, Staged};
        if !serving.well_formed() {
            return Ok(Refused);
        }
        if !matches!(
            self.get_blob_artifact_in_txn(wtxn, artifact_id),
            Ok(Some(_))
        ) {
            return Ok(Staged);
        }
        // Checks the ASSET is there and hashes to the descriptor's name, as
        // it streams.
        if !matches!(
            crate::ports::BlobStore::port_blob_reader(
                self,
                wtxn,
                &serving.content_hash,
                &mut |_: &mut dyn std::io::Read| Ok(()),
            ),
            Ok(true)
        ) {
            return Ok(Staged);
        }
        put_serving_blob_in_txn(&self.store, wtxn, artifact_id, version, serving)?;
        Ok(Applied)
    }
}
