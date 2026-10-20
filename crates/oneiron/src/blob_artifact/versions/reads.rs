//! The version chain's reads: the head, the version tree, one version's
//! metadata and its bytes. A filed compaction step's response artifact
//! (FIX 5977) is derived from every record its call read; its bytes leave
//! only while it and each of those stand, at every direct version read.

use heed::RoTxn;

use crate::Vault;
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{BodyStale, EntityStoreRead as _, body_readable_in_txn};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;

use super::super::body::decode_blob_artifact_body;
use super::super::made_by::made_by_text;
use super::super::provenance::{BLOB_VERSION_CLAIM_PREDICATE, blob_version_claim_value};
use super::super::store_keys::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use super::{BlobArtifactVersion, VERSIONS, read_blob_artifact_head_in_txn};

impl Vault {
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
        let mut versions = Vec::new();
        for entry in VERSIONS.iter_from(&self.store, &rtxn, artifact_id.as_bytes())? {
            let ((_, key_version), record) = entry?;
            let first_version = versions
                .first()
                .map_or(record.version, |first: &BlobArtifactVersion| first.version);
            let expected =
                versions
                    .last()
                    .map_or(Ok(record.version), |prior: &BlobArtifactVersion| {
                        prior
                            .version
                            .checked_add(1)
                            .ok_or(Error::ArithmeticOverflow("blob artifact version overflow"))
                    })?;
            if record.version != expected || key_version != record.version {
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
        let Some(record) = VERSIONS.get(&self.store, rtxn, &(*artifact_id, version))? else {
            return Ok(None);
        };
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
                    &made_by_text(&record.made_by)?,
                )
        {
            return Err(Error::CorruptedIndex("blob artifact version claim"));
        }
        Ok(Some(record))
    }

    /// The ASSET whose file holds version `version` of `artifact_id`, with
    /// the version's content hash, when the version reads here as
    /// [`Self::read_blob_artifact_version_in_txn`] reads it and its body is
    /// that file (FIX 5507): a serving door reads the file as its reader
    /// sees it. `None` for every other version, one whose body is in its row
    /// included, which that read reads as before.
    pub(crate) fn blob_artifact_version_file_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<(EntityId, [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN])>> {
        let Some(record) = VERSIONS.get(&self.store, rtxn, &(*artifact_id, version))? else {
            return Ok(None);
        };
        let asset = super::blob_artifact_asset_entity_id(&record.content_hash)?;
        let Some(row) = self.store.port_entity_record(rtxn, &asset)? else {
            return Ok(None);
        };
        if crate::store::asset_file_in_txn(&self.store, rtxn, &asset, &row.body)?.is_none()
            || !compaction_response_readable_in(self, rtxn, artifact_id)?
        {
            return Ok(None);
        }
        Ok(Some((asset, record.content_hash)))
    }

    /// Reads the stored bytes for one version, verifying the content hash on
    /// the way out. A compaction step's response whose words are withdrawn
    /// reads as absent ([`compaction_response_readable_in`]).
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
        let Some(record) = VERSIONS.get(&self.store, rtxn, &(*artifact_id, version))? else {
            return Ok(None);
        };
        if !compaction_response_readable_in(self, rtxn, artifact_id)? {
            return Ok(None);
        }
        read_blob_asset_in_txn(self, rtxn, &record.content_hash).map(Some)
    }

    /// One version record's stored bytes, which publication sync carries
    /// verbatim to the sync server's replica of this vault.
    pub(crate) fn blob_artifact_version_record_bytes_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        VERSIONS.get_bytes(&self.store, rtxn, &(*artifact_id, version))
    }
}

impl Vault {
    /// Lends one version's stored bytes to `lend` without copying them out
    /// of the store. The organ host uses it to fill a shared region once per
    /// content hash. Liveness (deletion, staleness) is checked on every call;
    /// the content hash is checked when `lend` asks for the bytes, so a
    /// caller that already holds them verified under this hash skips both
    /// the hash and the copy. `lend` runs inside the read transaction and
    /// must not open another one on this thread. A compaction step's
    /// response whose words are withdrawn lends nothing.
    pub fn lend_blob_artifact_version<R>(
        &self,
        artifact_id: &EntityId,
        version: u64,
        lend: impl FnOnce(&BlobArtifactVersion, BlobBytes<'_>) -> R,
    ) -> Result<Option<R>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(record) =
            self.blob_artifact_version_metadata_in_txn(&rtxn, artifact_id, version)?
        else {
            return Ok(None);
        };
        if !compaction_response_readable_in(self, &rtxn, artifact_id)? {
            return Ok(None);
        }
        let bytes = self
            .lend_blob_in_txn(&rtxn, &record.content_hash)?
            .ok_or(Error::EntityNotFound)?;
        Ok(Some(lend(
            &record,
            BlobBytes {
                bytes,
                hash: record.content_hash,
            },
        )))
    }
}

/// One version's bytes, borrowed from a read transaction.
#[derive(Debug)]
pub struct BlobBytes<'t> {
    bytes: std::borrow::Cow<'t, [u8]>,
    hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
}

impl<'t> BlobBytes<'t> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Checks the bytes against the version's content hash, then lends them.
    ///
    /// # Errors
    /// [`Error::CorruptedIndex`] when the stored bytes no longer hash to the
    /// version's content hash.
    pub fn verified(self) -> Result<std::borrow::Cow<'t, [u8]>> {
        if blake3::hash(&self.bytes).as_bytes() == &self.hash {
            Ok(self.bytes)
        } else {
            Err(Error::CorruptedIndex("blob content hash"))
        }
    }
}

fn read_blob_asset_in_txn(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    crate::ports::BlobStore::port_blob_get(vault, rtxn, content_hash)?.ok_or(Error::EntityNotFound)
}

/// Whether `artifact`'s version bytes may leave. A filed compaction step's
/// response artifact releases them only while its own body and every
/// record it was derived from stand ([`body_readable_in_txn`]); every other
/// artifact, and one whose row is gone or does not decode, reads as it
/// always has.
pub(crate) fn compaction_response_readable_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<bool> {
    let Some(record) = vault.store.port_entity_record(txn, artifact)? else {
        return Ok(true);
    };
    if record.entity_type != ENTITY_TYPE_BLOB_ARTIFACT {
        return Ok(true);
    }
    match decode_blob_artifact_body(&record.body) {
        Ok(body) if body.name == crate::compaction::COMPACTION_STEP_RESPONSE_NAME => {
            body_readable_in_txn(
                &vault.store,
                txn,
                artifact,
                &record.body,
                BodyStale::Withdrawn,
            )
        }
        _ => Ok(true),
    }
}
