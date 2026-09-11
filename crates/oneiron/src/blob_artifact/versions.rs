//! Blob version chain: version record codec and the Vault version-chain API.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSubject;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

use super::body::{BlobArtifactBody, decode_blob_artifact_body, encode_blob_artifact_body};
use super::provenance::{
    BLOB_VERSION_CLAIM_PREDICATE, BlobVersionProvenance, blob_version_claim_value,
    validate_provenance, write_provenance_value,
};
use super::store_keys::{
    BLOB_ARTIFACT_ASSET_ID_DOMAIN, BLOB_ARTIFACT_CONTENT_HASH_LEN, blob_artifact_asset_ref_key,
    blob_artifact_head_key, blob_artifact_version_key, blob_artifact_version_prefix, encode_value,
    entity_value, hash_from_value, read_value, require_entity_type, u64_value,
};
use crate::error::ArtifactError;

/// One record of the append-only version chain: content hash + provenance +
/// the `blob.version` claim id (the LEDGER event for this version).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactVersion {
    pub version: u64,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    pub provenance: BlobVersionProvenance,
    pub claim_id: EntityId,
    pub created_at: u64,
}

pub const BLOB_ARTIFACT_VERSION_RECORD_KEYS: [&str; 6] = [
    "version",
    "content_hash",
    "provenance",
    "run_ref",
    "claim_id",
    "created_at",
];

pub(super) const KEY_VERSION: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[0];

pub(super) const KEY_CONTENT_HASH: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[1];

pub(super) const KEY_PROVENANCE: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[2];

pub(super) const KEY_RUN_REF: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[3];

const KEY_CLAIM_ID: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[4];

const KEY_CREATED_AT: &str = BLOB_ARTIFACT_VERSION_RECORD_KEYS[5];

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
        validate_provenance(provenance)?;
        if bytes.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "blob artifact version bytes must be non-empty",
            )));
        }
        let content_hash = *blake3::hash(bytes).as_bytes();
        let asset_id = blob_artifact_asset_entity_id(&content_hash)?;
        let claim_id = EntityId::now();

        require_entity_type(
            &self.store,
            wtxn,
            artifact_id,
            ENTITY_TYPE_BLOB_ARTIFACT,
            "append target must be a BLOB_ARTIFACT entity",
        )?;
        let next_version = match read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)? {
            Some(head) if head.content_hash == content_hash => return Ok(head),
            Some(head) => head
                .version
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))?,
            None => 1,
        };
        let version_key = blob_artifact_version_key(artifact_id, next_version);
        if self.store.vault_meta.get(wtxn, &version_key)?.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "blob artifact version is already recorded",
            )));
        }

        let candidate = ClaimCandidate::new(
            BLOB_VERSION_CLAIM_PREDICATE,
            ClaimSubject::Entity(*artifact_id),
            blob_version_claim_value(next_version, &content_hash, provenance),
            1.0,
        );
        let envelope = WriteEnvelope::new(
            actor,
            provenance.claim_source(),
            WriteProvenance::new(write_provenance_value(provenance))?,
            provenance.approval_status(),
        );
        self.batch_in()
            .put(&asset_id, ENTITY_TYPE_ASSET, occurred, learned_at, bytes)
            .claim_candidate(&claim_id, candidate, &envelope, occurred, learned_at)
            .apply(wtxn)?;

        let record = BlobArtifactVersion {
            version: next_version,
            content_hash,
            provenance: provenance.clone(),
            claim_id,
            created_at: learned_at,
        };
        let encoded = encode_blob_artifact_version_record(&record)?;
        self.store.vault_meta.put(wtxn, &version_key, &encoded)?;
        self.store
            .vault_meta
            .put(wtxn, &blob_artifact_head_key(artifact_id), &encoded)?;
        self.store.vault_meta.put(
            wtxn,
            &blob_artifact_asset_ref_key(&content_hash, artifact_id),
            &[],
        )?;
        Ok(record)
    }

    pub fn blob_artifact_head(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Option<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)
    }

    /// Returns the full version chain, oldest first, verifying it is a
    /// contiguous append-only sequence starting at version 1.
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
            let expected = u64::try_from(versions.len())
                .map_err(|_| Error::ArithmeticOverflow("blob artifact version overflow"))?
                + 1;
            if record.version != expected || !key.ends_with(&record.version.to_be_bytes()) {
                return Err(Error::CorruptedIndex("blob artifact version chain"));
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
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &blob_artifact_version_key(artifact_id, version))?
        else {
            return Ok(None);
        };
        let record = decode_blob_artifact_version_record(&raw)?;
        if record.version != version {
            return Err(Error::CorruptedIndex("blob artifact version record"));
        }
        let claim = self
            .get_claim_in_txn(&rtxn, &record.claim_id)?
            .ok_or(Error::CorruptedIndex("blob artifact version claim"))?;
        if claim.predicate != BLOB_VERSION_CLAIM_PREDICATE
            || claim.subject != ClaimSubject::Entity(*artifact_id)
            || claim.value
                != blob_version_claim_value(version, &record.content_hash, &record.provenance)
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

fn encode_blob_artifact_version_record(record: &BlobArtifactVersion) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_VERSION),
            Value::Integer(record.version.into()),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(record.content_hash.to_vec()),
        ),
        (
            Value::from(KEY_PROVENANCE),
            Value::from(record.provenance.as_str()),
        ),
        (
            Value::from(KEY_RUN_REF),
            record.provenance.run_ref().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CLAIM_ID),
            Value::Binary(record.claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::Integer(record.created_at.into()),
        ),
    ]);
    encode_value(&value, "blob artifact version MessagePack encode failed")
}

pub(super) fn decode_blob_artifact_version_record(bytes: &[u8]) -> Result<BlobArtifactVersion> {
    let value = read_value(bytes, "version record")?;
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "version record must be a MessagePack map",
        )));
    };

    let mut version = None;
    let mut content_hash = None;
    let mut provenance_kind: Option<String> = None;
    let mut run_ref: Option<Option<String>> = None;
    let mut claim_id = None;
    let mut created_at = None;
    let mut seen = [false; BLOB_ARTIFACT_VERSION_RECORD_KEYS.len()];

    for (key, value) in &entries {
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "version record keys must be strings",
            )))?;
        let Some(index) = BLOB_ARTIFACT_VERSION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "version record key is not in the pinned BLOB_ARTIFACT_VERSION_RECORD_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "duplicate version record key",
            )));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_VERSION_RECORD_KEYS[index] {
            KEY_VERSION => version = Some(u64_value(value, "version")?),
            KEY_CONTENT_HASH => content_hash = Some(hash_from_value(value, "content_hash")?),
            KEY_PROVENANCE => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidBlobArtifactBody("provenance must be a UTF-8 string"),
                ))?;
                provenance_kind = Some(text.to_owned());
            }
            KEY_RUN_REF => {
                run_ref = Some(match value {
                    Value::Nil => None,
                    other => Some(
                        other
                            .as_str()
                            .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                                "run_ref must be a UTF-8 string or nil",
                            )))?
                            .to_owned(),
                    ),
                });
            }
            KEY_CLAIM_ID => claim_id = Some(entity_value(value, "claim_id")?),
            KEY_CREATED_AT => created_at = Some(u64_value(value, "created_at")?),
            _ => unreachable!("index resolved from BLOB_ARTIFACT_VERSION_RECORD_KEYS"),
        }
    }

    let version = version.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
        "missing required version record key version",
    )))?;
    if version == 0 {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "version record version must be at least 1",
        )));
    }
    let provenance = BlobVersionProvenance::from_parts(
        &provenance_kind.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key provenance",
        )))?,
        run_ref.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key run_ref",
        )))?,
    )?;
    validate_provenance(&provenance)?;
    Ok(BlobArtifactVersion {
        version,
        content_hash: content_hash.ok_or(Error::Artifact(
            ArtifactError::InvalidBlobArtifactBody(
                "missing required version record key content_hash",
            ),
        ))?,
        provenance,
        claim_id: claim_id.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key claim_id",
        )))?,
        created_at: created_at.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key created_at",
        )))?,
    })
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
    let asset_id = blob_artifact_asset_entity_id(content_hash)?;
    let Some(raw) = vault.store.entities.get(rtxn, asset_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
        return Err(crate::secret_custody::reject_secret_custody_byte());
    }
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "version content hash did not resolve to an ASSET",
        )));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if blake3::hash(&body).as_bytes() != content_hash {
        return Err(Error::CorruptedIndex("blob artifact asset content hash"));
    }
    Ok(body)
}

pub(super) fn blob_artifact_asset_entity_id(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(BLOB_ARTIFACT_ASSET_ID_DOMAIN, &[content_hash])
}
