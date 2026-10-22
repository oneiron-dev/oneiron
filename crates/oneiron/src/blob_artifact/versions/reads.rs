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
use crate::secret_custody::{SecretSight, masked_file_in_txn, sighted_bytes_in_txn};

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

    /// Returns the version tree that stays, in version order. Verifies
    /// strictly ascending scalar versions, each parent earlier than its
    /// version, and the current head as the greatest of them. A version a
    /// response pin's release took (FIX 6225) leaves its gap, and a version
    /// descending from it names a parent no longer here: no surviving record
    /// is renumbered or rewritten.
    pub fn blob_artifact_versions(
        &self,
        artifact_id: &EntityId,
    ) -> Result<Vec<BlobArtifactVersion>> {
        let rtxn = self.store.env.read_txn()?;
        let mut versions: Vec<BlobArtifactVersion> = Vec::new();
        for entry in VERSIONS.iter_from(&self.store, &rtxn, artifact_id.as_bytes())? {
            let ((_, key_version), record) = entry?;
            if key_version != record.version
                || versions
                    .last()
                    .is_some_and(|prior| prior.version >= record.version)
            {
                return Err(Error::CorruptedIndex("blob artifact version chain"));
            }
            if record
                .parent_version
                .is_some_and(|parent| parent == 0 || parent >= record.version)
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

    /// Whether `artifact_id`'s version bytes may leave
    /// ([`compaction_response_readable_in`]), for a reader that finds them
    /// through a published blob's serving descriptor (FIX 1195).
    pub(crate) fn blob_artifact_bytes_readable_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
    ) -> Result<bool> {
        compaction_response_readable_in(self, rtxn, artifact_id)
    }
}

impl Vault {
    /// Lends one version's bytes to `lend` as `sight` reads them, without
    /// copying stored bytes out of the store. The organ host uses it to fill
    /// a shared region once per lent hash. Liveness (deletion, staleness) is
    /// checked on every call. `lend` runs inside the read transaction and
    /// must not open another one on this thread. A compaction step's
    /// response whose words are withdrawn lends nothing.
    ///
    /// A masked reader of a body the secret mask marked is lent the masked
    /// copy, made as the whole-body door makes it from the stored bytes,
    /// verified first (FIX 6508): an inline body by `sighted_bytes_in_txn`,
    /// one kept in its ASSET's file by `sighted_body_file_in_txn`. The owner, a
    /// granted agent, and every reader of a body no mark covers are lent the
    /// stored bytes, whose content hash is checked when `lend` asks for
    /// them, so a caller that already holds them verified under this hash
    /// skips both the hash and the copy.
    pub fn lend_blob_artifact_version<R>(
        &self,
        artifact_id: &EntityId,
        version: u64,
        sight: SecretSight,
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
        if sight == SecretSight::Masked
            && masked_file_in_txn(&self.store, &rtxn, &record.content_hash)?.is_some()
        {
            let copy = self.masked_version_copy_in_txn(&rtxn, artifact_id, &record)?;
            return Ok(Some(lend(&record, BlobBytes::masked_copy(copy))));
        }
        let bytes = self
            .lend_blob_in_txn(&rtxn, &record.content_hash)?
            .ok_or(Error::EntityNotFound)?;
        Ok(Some(lend(
            &record,
            BlobBytes {
                bytes,
                hash: record.content_hash,
                masked: false,
            },
        )))
    }

    /// The masked copy of `record`'s body, which a mark covers: a body kept
    /// in its ASSET's file is filled as the checked reader verifies it, and
    /// an inline one is verified under the version's content hash before it
    /// is masked. Every refusal is the whole-body door's.
    fn masked_version_copy_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        artifact_id: &EntityId,
        record: &BlobArtifactVersion,
    ) -> Result<Vec<u8>> {
        if let Some((asset, hash)) =
            self.blob_artifact_version_file_in_txn(rtxn, artifact_id, record.version)?
        {
            return self
                .sighted_body_file_in_txn(rtxn, &asset, &hash, SecretSight::Masked)?
                .ok_or(Error::EntityNotFound);
        }
        let stored = BlobBytes {
            bytes: self
                .lend_blob_in_txn(rtxn, &record.content_hash)?
                .ok_or(Error::EntityNotFound)?,
            hash: record.content_hash,
            masked: false,
        }
        .verified()?;
        sighted_bytes_in_txn(&self.store, rtxn, stored.into_owned(), SecretSight::Masked)
    }
}

/// One version's bytes, borrowed from a read transaction, or the masked copy
/// a masked reader is lent.
#[derive(Debug)]
pub struct BlobBytes<'t> {
    bytes: std::borrow::Cow<'t, [u8]>,
    /// The BLAKE3 of the bytes lent: the version's content hash for its
    /// stored bytes, the copy's own for a masked copy.
    hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    /// A masked copy, hashed as it was lent: its stored bytes were verified
    /// before they were masked.
    masked: bool,
}

impl<'t> BlobBytes<'t> {
    fn masked_copy(copy: Vec<u8>) -> Self {
        Self {
            hash: *blake3::hash(&copy).as_bytes(),
            bytes: std::borrow::Cow::Owned(copy),
            masked: true,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The BLAKE3 of the bytes lent (FIX 6508): the version's content hash
    /// for its stored bytes, the copy's own for a masked copy. A cache or a
    /// receipt names what the reader saw by it, never by the stored bytes'
    /// hash alone.
    #[must_use]
    pub const fn hash(&self) -> &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN] {
        &self.hash
    }

    /// Checks stored bytes against the version's content hash, then lends
    /// them. A masked copy, made from stored bytes verified first, is lent
    /// as it is.
    ///
    /// # Errors
    /// [`Error::CorruptedIndex`] when the stored bytes no longer hash to the
    /// version's content hash.
    pub fn verified(self) -> Result<std::borrow::Cow<'t, [u8]>> {
        if self.masked || blake3::hash(&self.bytes).as_bytes() == &self.hash {
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
