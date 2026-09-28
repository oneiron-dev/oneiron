//! Blob version chain: version record codec and the Vault version-chain API.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSubject;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::body::{BlobArtifactBody, decode_blob_artifact_body, encode_blob_artifact_body};
use super::provenance::{
    BLOB_VERSION_CLAIM_PREDICATE, BlobVersionProvenance, blob_version_claim_value,
    validate_provenance, write_provenance_value,
};
use super::store_keys::{
    BLOB_ARTIFACT_ASSET_ID_DOMAIN, BLOB_ARTIFACT_CONTENT_HASH_LEN, blob_artifact_head_key,
    blob_artifact_highwater_key, blob_artifact_version_key, blob_artifact_version_prefix,
    require_entity_type,
};
pub(super) use super::version_codec::decode_blob_artifact_version_record;
use super::version_codec::encode_blob_artifact_version_record;
use crate::error::ArtifactError;

/// The calculator that last computed an artifact version's cached values.
/// An upload or a version that was never recalculated has no stamp; absence is
/// explicit in both the version record and its ledger claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalcEngineStamp {
    engine: String,
    version: String,
}

impl CalcEngineStamp {
    pub fn new(engine: impl Into<String>, version: impl Into<String>) -> Result<Self> {
        let stamp = Self {
            engine: engine.into(),
            version: version.into(),
        };
        stamp.validate()?;
        Ok(stamp)
    }

    #[must_use]
    pub fn engine(&self) -> &str {
        &self.engine
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    fn validate(&self) -> Result<()> {
        for text in [&self.engine, &self.version] {
            if text.trim().is_empty() || text.len() > 128 {
                return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                    "calc engine and version must be non-empty and at most 128 bytes",
                )));
            }
            crate::batch::secret_scan::scan_metadata_field(text)?;
        }
        Ok(())
    }
}

/// One record of the append-only version tree: content hash + provenance +
/// the `blob.version` claim id (the LEDGER event for this version).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactVersion {
    pub version: u64,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    pub provenance: BlobVersionProvenance,
    /// `None` means no known calculator computed the cached values.
    pub calc_engine: Option<CalcEngineStamp>,
    pub claim_id: EntityId,
    pub created_at: u64,
    /// Export presentation pinned when this version was appended, not read
    /// from the mutable artifact body at serve time.
    pub export_name: String,
    pub export_media_type: String,
    /// The version this record descends from. Absent for roots and legacy rows.
    pub parent_version: Option<u64>,
    /// The selected base of an explicit fork; absent on ordinary head appends.
    pub fork_of_version: Option<u64>,
}

pub const BLOB_ARTIFACT_VERSION_RECORD_KEYS: [&str; 12] = [
    "version",
    "content_hash",
    "provenance",
    "run_ref",
    "claim_id",
    "created_at",
    "parent_version",
    "fork_of_version",
    "calc_engine",
    "calc_engine_version",
    "export_name",
    "export_media_type",
];

pub(super) const KEY_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[0];

pub(super) const KEY_CONTENT_HASH: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[1];

pub(super) const KEY_PROVENANCE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[2];

pub(super) const KEY_RUN_REF: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[3];

pub(super) const KEY_CLAIM_ID: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[4];

pub(super) const KEY_CREATED_AT: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[5];

pub(super) const KEY_PARENT_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[6];

pub(super) const KEY_FORK_OF_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[7];

pub(super) const KEY_CALC_ENGINE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[8];

pub(super) const KEY_CALC_ENGINE_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[9];

pub(super) const KEY_EXPORT_NAME: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[10];
pub(super) const KEY_EXPORT_MEDIA_TYPE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[11];

impl Vault {
    pub fn put_blob_artifact(
        &self,
        id: &EntityId,
        body: &BlobArtifactBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_blob_artifact_body(body)?;
        self.put_entity(id, ENTITY_TYPE_BLOB_ARTIFACT, occurred, learned_at, &data)
    }

    pub fn get_blob_artifact(&self, id: &EntityId) -> Result<Option<BlobArtifactBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_blob_artifact_in_txn(&rtxn, id)
    }

    pub(crate) fn get_blob_artifact_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<BlobArtifactBody>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        if header.entity_type != ENTITY_TYPE_BLOB_ARTIFACT {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "entity is not a type-85 BLOB_ARTIFACT",
            )));
        }
        decode_blob_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Appends one version to the artifact's append-only chain.
    ///
    /// The whole append is ONE LMDB write transaction: the content-addressed
    /// ASSET bytes (blake3), the `blob.version` claim — the LEDGER event —
    /// the version record, the head record, and the asset reference row all
    /// land together or roll back together, so a failed append can never
    /// leave an orphan claim or asset asserting a version that does not
    /// exist. Re-appending the exact bytes of the current head is a dedupe
    /// no-op that returns the existing head version.
    pub fn append_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.with_write_txn(|wtxn| {
            self.append_blob_artifact_version_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                learned_at,
            )
        })
    }

    /// Appends a new version descending from any existing version of this artifact.
    /// The scalar version number still advances at head+1; only the ancestry
    /// pointer branches. Unlike an ordinary append, identical bytes do not
    /// suppress the explicit fork event.
    #[expect(clippy::too_many_arguments)]
    pub fn fork_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        parent_version: u64,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.with_write_txn(|wtxn| {
            self.append_blob_artifact_version_with_parent_in_txn(
                wtxn,
                artifact_id,
                bytes,
                provenance,
                actor,
                occurred,
                learned_at,
                Some(parent_version),
            )
        })
    }

    /// Transaction-composable body of [`Vault::append_blob_artifact_version`].
    ///
    /// ARTL-4 settle-select needs the version append, its re-anchor sweep, and
    /// the consume-once ledger insert to commit or roll back as one unit, so it
    /// drives this against a shared `wtxn` rather than the self-contained public
    /// method's own transaction.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_with_parent_in_txn(
            wtxn,
            artifact_id,
            bytes,
            provenance,
            actor,
            occurred,
            learned_at,
            None,
        )
    }

    /// Settle's append door, with the calculator that produced cached values.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn append_blob_artifact_version_with_engine_and_parent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        calc_engine: Option<&CalcEngineStamp>,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_with_parent_and_engine_in_txn(
            wtxn,
            artifact_id,
            bytes,
            provenance,
            actor,
            occurred,
            learned_at,
            fork_parent,
            calc_engine,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn append_blob_artifact_version_with_parent_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
    ) -> Result<BlobArtifactVersion> {
        self.append_blob_artifact_version_with_parent_and_engine_in_txn(
            wtxn,
            artifact_id,
            bytes,
            provenance,
            actor,
            occurred,
            learned_at,
            fork_parent,
            None,
        )
    }

    #[expect(clippy::too_many_arguments)]
    fn append_blob_artifact_version_with_parent_and_engine_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact_id: &EntityId,
        bytes: &[u8],
        provenance: &BlobVersionProvenance,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
        fork_parent: Option<u64>,
        calc_engine: Option<&CalcEngineStamp>,
    ) -> Result<BlobArtifactVersion> {
        validate_provenance(provenance)?;
        if let Some(stamp) = calc_engine {
            stamp.validate()?;
        }
        if bytes.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "blob artifact version bytes must be non-empty",
            )));
        }
        let content_hash = *blake3::hash(bytes).as_bytes();
        let claim_id = EntityId::from_bytes(self.store.clock.ulid()?)?;

        require_entity_type(
            &self.store,
            wtxn,
            artifact_id,
            ENTITY_TYPE_BLOB_ARTIFACT,
            "append target must be a BLOB_ARTIFACT entity",
        )?;
        let body = self
            .get_blob_artifact_in_txn(wtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let fingerprint =
            crate::ingest::prepare_blob_artifact_birth(&self.store, wtxn, artifact_id, bytes)?;
        let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
        let highwater = read_blob_artifact_highwater_in_txn(&self.store, wtxn, artifact_id)?;
        if head
            .as_ref()
            .is_some_and(|head| highwater != Some(head.version))
        {
            return Err(Error::CorruptedIndex("blob artifact version highwater"));
        }
        let parent_version = match (fork_parent, &head) {
            (Some(parent), Some(head)) if parent > 0 && parent <= head.version => {
                let key = blob_artifact_version_key(artifact_id, parent);
                let raw = self
                    .store
                    .vault_meta
                    .get(wtxn, &key)?
                    .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                        "fork parent version does not exist",
                    )))?;
                if decode_blob_artifact_version_record(&raw)?.version != parent {
                    return Err(Error::CorruptedIndex("blob artifact fork parent"));
                }
                Some(parent)
            }
            (Some(_), _) => {
                return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                    "fork parent version does not exist",
                )));
            }
            (None, Some(head)) if head.content_hash == content_hash => {
                fingerprint.persist(&self.store, wtxn, artifact_id)?;
                return Ok(head.clone());
            }
            (None, Some(head)) => Some(head.version),
            (None, None) => None,
        };
        // Deletion removes the current chain but never its high-water mark:
        // an old immutable URL must not identify a new incarnation's bytes.
        let previous_version = head
            .as_ref()
            .map_or(highwater.unwrap_or(0), |head| head.version);
        let next_version = previous_version
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))?;
        let version_key = blob_artifact_version_key(artifact_id, next_version);
        if self.store.vault_meta.get(wtxn, &version_key)?.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "blob artifact version is already recorded",
            )));
        }

        let candidate = ClaimCandidate::new(
            BLOB_VERSION_CLAIM_PREDICATE,
            ClaimSubject::Entity(*artifact_id),
            blob_version_claim_value(
                next_version,
                &content_hash,
                provenance,
                parent_version,
                fork_parent,
                calc_engine,
            ),
            1.0,
        );
        let mut envelope = WriteEnvelope::new(
            actor,
            provenance.claim_source(),
            WriteProvenance::new(write_provenance_value(provenance))?,
            provenance.approval_status(),
        );
        // The artifact is the logical owner of this content-addressed version.
        // The ASSET bytes and head/index rows are supporting effects of it;
        // the canonical claim is a second semantic content owner.
        self.authorize_shared_content_write_in_txn(wtxn, *artifact_id, &actor)?;
        crate::ports::BlobStore::port_blob_put(
            self,
            wtxn,
            artifact_id,
            bytes,
            occurred,
            learned_at,
        )?;
        self.sign_retained_machine_claim_in_txn(&*wtxn, &claim_id, &candidate, &mut envelope)?;
        self.batch_in()
            .claim_candidate(&claim_id, candidate, &envelope, occurred, learned_at)
            .apply_actor(wtxn, &actor)?;

        let record = BlobArtifactVersion {
            version: next_version,
            content_hash,
            provenance: provenance.clone(),
            calc_engine: calc_engine.cloned(),
            claim_id,
            created_at: learned_at,
            export_name: body.name,
            export_media_type: body.media_type,
            parent_version,
            fork_of_version: fork_parent,
        };
        let recorded_at = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
        crate::ports::ChangeLogStore::port_changelog_append(
            self,
            wtxn,
            &crate::ports::ChangeLogRecord {
                id: self.store.clock.ulid()?,
                entity: *artifact_id,
                op: crate::ports::ChangeOp::Update,
                actor_principal: actor.entity_ref(),
                actor_person: None,
                occurred_at: occurred.start,
                recorded_at,
                input_hash: content_hash,
                patch: None,
                reason: Some("blob version appended".into()),
            },
        )?;
        let encoded = encode_blob_artifact_version_record(&record)?;
        self.store.vault_meta.put(wtxn, &version_key, &encoded)?;
        self.store
            .vault_meta
            .put(wtxn, &blob_artifact_head_key(artifact_id), &encoded)?;
        self.store.vault_meta.put(
            wtxn,
            &blob_artifact_highwater_key(artifact_id),
            &next_version.to_be_bytes(),
        )?;
        fingerprint.persist(&self.store, wtxn, artifact_id)?;
        Ok(record)
    }

    pub fn blob_artifact_head(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Option<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)
    }

    /// Returns the full version tree in append order. Verifies contiguous
    /// scalar versions, earlier existing parents, and the current head.
    pub fn blob_artifact_versions(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = blob_artifact_version_prefix(artifact_id);
        let mut versions = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, raw) = entry?;
            let record = decode_blob_artifact_version_record(&raw)?;
            let first_version = versions
                .first()
                .map_or(record.version, |first: &BlobArtifactVersion| first.version);
            let expected =
                versions
                    .last()
                    .map_or(Ok(record.version), |previous: &BlobArtifactVersion| {
                        previous
                            .version
                            .checked_add(1)
                            .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))
                    })?;
            if record.version != expected || !key.ends_with(&record.version.to_be_bytes()) {
                return Err(Error::CorruptedIndex("blob artifact version chain"));
            }
            if let Some(parent) = record.parent_version
                && (parent < first_version
                    || parent >= record.version
                    || versions.get((parent - first_version) as usize).is_none())
            {
                return Err(Error::CorruptedIndex("blob artifact version parent"));
            }
            versions.push(record);
        }
        if let Some(head) = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)? {
            if versions.last() != Some(&head) {
                return Err(Error::CorruptedIndex("blob artifact version head"));
            }
        } else if !versions.is_empty() {
            return Err(Error::CorruptedIndex("blob artifact version head"));
        }
        Ok(versions)
    }

    /// Reads metadata for exactly one version without walking the version
    /// chain or loading content bytes. Two direct reads in one snapshot bind
    /// the record to its persisted `blob.version` claim: the subject must be
    /// the requested artifact, and the version, hash, and provenance must
    /// match. An absent version returns `None`; malformed records or missing
    /// or mismatched claims fail closed. This does not validate the chain,
    /// resolve the ASSET, or authorize secret-taint reuse.
    pub fn blob_artifact_version_metadata(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        self.blob_artifact_version_metadata_in_txn(&rtxn, artifact_id, version)
    }

    pub(crate) fn blob_artifact_version_metadata_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<BlobArtifactVersion>> {
        let Some(raw) = self
            .store
            .vault_meta
            .get(rtxn, &blob_artifact_version_key(artifact_id, version))?
        else {
            return Ok(None);
        };
        let record = decode_blob_artifact_version_record(&raw)?;
        if record.version != version {
            return Err(Error::CorruptedIndex("blob artifact version record"));
        }
        let claim = self
            .get_claim_in_txn(rtxn, &record.claim_id)?
            .ok_or(Error::CorruptedIndex("blob artifact version claim"))?;
        if claim.predicate != BLOB_VERSION_CLAIM_PREDICATE
            || claim.subject != ClaimSubject::Entity(*artifact_id)
            || claim.value
                != blob_version_claim_value(
                    version,
                    &record.content_hash,
                    &record.provenance,
                    record.parent_version,
                    record.fork_of_version,
                    record.calc_engine.as_ref(),
                )
        {
            return Err(Error::CorruptedIndex("blob artifact version claim"));
        }
        Ok(Some(record))
    }

    /// Reads the stored bytes for one version, verifying the content hash on
    /// the way out.
    pub fn read_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.read_blob_artifact_version_in_txn(&rtxn, artifact_id, version)
    }

    pub(crate) fn read_blob_artifact_version_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self
            .store
            .vault_meta
            .get(rtxn, &blob_artifact_version_key(artifact_id, version))?
        else {
            return Ok(None);
        };
        let record = decode_blob_artifact_version_record(&raw)?;
        read_blob_asset_in_txn(self, rtxn, &record.content_hash).map(Some)
    }
}

fn read_blob_artifact_highwater_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
) -> Result<Option<u64>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &blob_artifact_highwater_key(artifact_id))?
    else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("blob artifact version highwater"))?;
    let version = u64::from_be_bytes(bytes);
    if version == 0 {
        return Err(Error::CorruptedIndex("blob artifact version highwater"));
    }
    Ok(Some(version))
}

pub(crate) fn read_blob_artifact_head_in_txn(
    store: &Store,
    rtxn: &RoTxn<'_>,
    artifact_id: &EntityId,
) -> Result<Option<BlobArtifactVersion>> {
    let Some(raw) = store
        .vault_meta
        .get(rtxn, &blob_artifact_head_key(artifact_id))?
    else {
        return Ok(None);
    };
    decode_blob_artifact_version_record(&raw).map(Some)
}

fn read_blob_asset_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    crate::ports::BlobStore::port_blob_get(vault, rtxn, content_hash)?.ok_or(Error::EntityNotFound)
}

pub(crate) fn blob_artifact_asset_entity_id(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(BLOB_ARTIFACT_ASSET_ID_DOMAIN, &[content_hash])
}
