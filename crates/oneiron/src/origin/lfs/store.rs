//! Object plane: Vault adapter methods, shared expectation gate, key builders, record codec.

use super::{
    LfsAdmission, LfsAssetClass, LfsOid, LfsPathPolicy, LfsPointerIntent, VAULT_LFS_OID_LEN,
};
use crate::Vault;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, Error, Result};
use crate::temporal::TimeRange;

/// Schema version of both `vault_meta` row families below.
pub const VAULT_LFS_SCHEMA_VERSION: u8 = 2;

/// Object family: `prefix ++ 32 raw OID bytes`.
///
/// The prefix ends in the version separator `v1:` so a future `v10:` can never
/// be a prefix-scan of `v1` (`store::short_id_alias` prefix law).
pub const VAULT_LFS_OBJECT_KEY_PREFIX: &[u8] = b"origin:lfs:object:v1:";

/// Ref-attachment family:
/// `prefix ++ 16B repo_id ++ 0x00 ++ ref_name ++ 0x00 ++ 32B OID`.
pub const VAULT_LFS_REF_KEY_PREFIX: &[u8] = b"origin:lfs:ref:v1:";

/// Domain separator for deterministic LFS ASSET ids.
pub const VAULT_LFS_ASSET_ID_DOMAIN: &[u8] = b"oneiron:origin-lfs-asset:v1";

/// Domain separator for the repository key an attachment row is scoped to.
pub const VAULT_LFS_REPO_ID_DOMAIN: &[u8] = b"oneiron:origin-lfs-repo:v1";

/// The one Git-LFS transfer adapter this origin serves.
pub const LFS_BASIC_TRANSFER: &str = "basic";

/// The Git-LFS batch API media type.
pub const LFS_JSON_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// `asset_id(16) ++ size u64 LE(8) ++ created_at u64 LE(8)`.
const LFS_OBJECT_RECORD_LEN: usize = ENTITY_ID_LEN * 2 + 16;

/// The key separator inside an attachment key. A git ref name can never carry
/// a NUL, so the repo_id/ref_name/OID fields stay unambiguously framed.
const LFS_REF_KEY_SEPARATOR: u8 = 0;

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------
/// One durable LFS object record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct VaultLfsObject {
    /// The object id, which is the SHA-256 of the stored bytes.
    pub oid: LfsOid,
    /// The deterministic ASSET entity carrying the bytes.
    pub asset_id: EntityId,
    /// The stored byte length.
    pub size_bytes: u64,
    /// When this vault first learned these bytes.
    pub created_at: u64,
    pub(super) ref_owner: EntityId,
}

/// What one upload did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LfsPutOutcome {
    /// The durable record, existing or newly written.
    pub object: VaultLfsObject,
    /// Whether the bytes were already stored, so nothing was written.
    pub deduplicated: bool,
}

// ---------------------------------------------------------------------------
// Shared expectation check
// ---------------------------------------------------------------------------
/// The one gate an upload passes BEFORE anything is written.
///
/// Shared by the engine put and the HTTP upload route on purpose: "the bytes
/// are what the client said they are" must be one rule with one spelling, so
/// no transport can accidentally hold a weaker one.
pub fn check_lfs_expectation(
    expected_oid: LfsOid,
    expected_size: Option<u64>,
    bytes: &[u8],
) -> Result<()> {
    let actual_size = u64::try_from(bytes.len())
        .map_err(|_| Error::ArithmeticOverflow("lfs object length exceeds u64"))?;
    check_lfs_digest(
        expected_oid,
        expected_size,
        LfsOid::digest(bytes),
        actual_size,
    )
}

pub(super) fn check_lfs_digest(
    expected_oid: LfsOid,
    expected_size: Option<u64>,
    actual_oid: LfsOid,
    actual_size: u64,
) -> Result<()> {
    if expected_size.is_some_and(|expected| expected != actual_size) {
        return Err(Error::Artifact(ArtifactError::InvalidLfsObject(
            "declared lfs size does not match the body length",
        )));
    }
    if actual_oid != expected_oid {
        return Err(Error::Artifact(ArtifactError::InvalidLfsObject(
            "body sha256 does not match the declared lfs oid",
        )));
    }
    Ok(())
}

/// The repository key attachment rows are scoped to.
///
/// Derived from the object store's proven identity rather than a `RepoRef`
/// spelling: a `RepoRef` pins a commit and therefore changes every push, while
/// the attachment plane must key on the repository that outlives them.
pub fn lfs_repo_id(repo_identity: &str) -> Result<EntityId> {
    entity_id_from_hash_material(VAULT_LFS_REPO_ID_DOMAIN, &[repo_identity.as_bytes()])
}

impl Vault {
    /// Convenience upload for in-memory callers; streaming callers use `put_lfs_object_stream`.
    pub fn put_lfs_object(
        &self,
        oid: LfsOid,
        bytes: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<LfsPutOutcome> {
        self.put_lfs_object_stream(
            oid,
            Some(bytes.len() as u64),
            std::io::Cursor::new(bytes),
            occurred,
            learned_at,
        )
    }

    /// The live object record. Deleted OIDs never resolve even during deferred byte reclamation.
    pub fn lfs_object(&self, oid: LfsOid) -> Result<Option<VaultLfsObject>> {
        let txn = self.store.env.read_txn()?;
        if self
            .store
            .vault_meta
            .get(
                &txn,
                &super::chunks::key(super::lifecycle::DELETED, oid.as_bytes()),
            )?
            .is_some()
        {
            return Ok(None);
        }
        self.store
            .vault_meta
            .get(&txn, &lfs_object_key(&oid))?
            .map(|raw| decode_lfs_object_record(oid, &raw))
            .transpose()
    }

    /// Whether a live object has this exact declared size.
    pub fn has_lfs_object(&self, oid: LfsOid, size: u64) -> Result<bool> {
        Ok(self.lfs_object(oid)?.is_some_and(|o| o.size_bytes == size))
    }

    /// Convenience buffered read. Servers use `write_lfs_object_to` instead.
    pub fn get_lfs_object(&self, oid: LfsOid) -> Result<Option<Vec<u8>>> {
        let mut bytes = Vec::new();
        if !self.write_lfs_object_to(oid, &mut bytes)? {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    /// Verifies all chunks and the Git-LFS pointer without collecting the object.
    pub fn verify_lfs_object(&self, oid: LfsOid, size: u64) -> Result<bool> {
        if !self.has_lfs_object(oid, size)? {
            return Ok(false);
        }
        self.write_lfs_object_to(oid, &mut std::io::sink())
    }

    /// Streams verified chunks to a writer with at most one chunk resident.
    /// A corrupt chunk is rejected before its bytes are passed to the writer.
    pub fn write_lfs_object_to<W: std::io::Write>(
        &self,
        oid: LfsOid,
        writer: &mut W,
    ) -> Result<bool> {
        use sha2::{Digest, Sha256};
        let Some(manifest) = self.lfs_manifest(oid)? else {
            return Ok(false);
        };
        let mut sha = Sha256::new();
        for chunk in &manifest.chunks {
            // No long-lived LMDB reader: deletion remains visible between chunks.
            if self.lfs_object(oid)?.is_none() {
                return Err(super::chunks::invalid("lfs object deleted during read"));
            }
            let bytes = super::chunks::read_chunk(self, chunk)?;
            sha.update(&bytes);
            writer.write_all(&bytes)?;
        }
        let digest: [u8; 32] = sha.finalize().into();
        if digest != *oid.as_bytes() {
            return Err(Error::CorruptedIndex("lfs pointer digest"));
        }
        Ok(true)
    }

    /// Records that one git ref references one LFS object.
    pub fn attach_lfs_object_to_git_ref(
        &self,
        repo_id: EntityId,
        ref_name: &str,
        oid: LfsOid,
        learned_at: u64,
    ) -> Result<()> {
        let key = lfs_ref_key(&repo_id, ref_name, &oid);
        self.with_write_txn(|wtxn| {
            if self
                .store
                .vault_meta
                .get(
                    wtxn,
                    &super::chunks::key(super::lifecycle::DELETED, oid.as_bytes()),
                )?
                .is_some()
                || self
                    .store
                    .vault_meta
                    .get(wtxn, &lfs_object_key(&oid))?
                    .is_none()
            {
                return Err(super::chunks::invalid(
                    "cannot attach missing or deleted lfs object",
                ));
            }
            self.store
                .vault_meta
                .put(wtxn, &key, &learned_at.to_le_bytes())?;
            Ok(())
        })
    }

    /// Drops one ref's attachment rows and returns how many were removed.
    ///
    /// Rows come and go; BYTES do not. An object another ref still references
    /// survives untouched, and so does an object no ref references at all —
    /// this is not a garbage collector and must never become one by accident.
    pub fn detach_lfs_objects_from_git_ref(
        &self,
        repo_id: EntityId,
        ref_name: &str,
    ) -> Result<u64> {
        let prefix = lfs_ref_prefix(&repo_id, ref_name);
        self.with_write_txn(|wtxn| {
            let mut keys = Vec::new();
            for entry in self.store.vault_meta.prefix_iter(wtxn, &prefix)? {
                let (key, _) = entry?;
                keys.push(key.to_vec());
            }
            let removed = u64::try_from(keys.len())
                .map_err(|_| Error::ArithmeticOverflow("lfs ref row count exceeds u64"))?;
            for key in keys {
                self.store.vault_meta.delete(wtxn, &key)?;
            }
            Ok(removed)
        })
    }

    /// The object ids one git ref currently references.
    pub fn lfs_git_ref_objects(&self, repo_id: EntityId, ref_name: &str) -> Result<Vec<LfsOid>> {
        let prefix = lfs_ref_prefix(&repo_id, ref_name);
        let rtxn = self.store.env.read_txn()?;
        let mut oids = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (key, _) = entry?;
            let raw: [u8; VAULT_LFS_OID_LEN] = key
                .get(key.len().saturating_sub(VAULT_LFS_OID_LEN)..)
                .and_then(|tail| tail.try_into().ok())
                .ok_or(Error::CorruptedIndex("vault lfs ref key"))?;
            if self
                .store
                .vault_meta
                .get(&rtxn, &super::chunks::key(super::lifecycle::DELETED, &raw))?
                .is_none()
            {
                oids.push(LfsOid::from_bytes(raw));
            }
        }
        Ok(oids)
    }

    /// Classifies one pointer. Pure: the CALLER enforces the outcome.
    ///
    /// Kept free of enforcement on purpose — publication policy belongs to the
    /// landing that knows what a ref move means, and a classifier that also
    /// blocked would make the two impossible to test apart.
    pub fn admit_lfs_pointer(
        &self,
        policy: &dyn LfsPathPolicy,
        intent: &LfsPointerIntent,
    ) -> Result<LfsAdmission> {
        Ok(match policy.classify(intent.repo_id, &intent.path)? {
            LfsAssetClass::RepositoryLarge => LfsAdmission::StoreInLfs,
            LfsAssetClass::BuildRequired => LfsAdmission::KeepInGit,
        })
    }
}

pub(super) fn lfs_object_key(oid: &LfsOid) -> Vec<u8> {
    let mut key = Vec::with_capacity(VAULT_LFS_OBJECT_KEY_PREFIX.len() + VAULT_LFS_OID_LEN);
    key.extend_from_slice(VAULT_LFS_OBJECT_KEY_PREFIX);
    key.extend_from_slice(oid.as_bytes());
    key
}

fn lfs_ref_prefix(repo_id: &EntityId, ref_name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        VAULT_LFS_REF_KEY_PREFIX.len() + ENTITY_ID_LEN + ref_name.len() + 2 + VAULT_LFS_OID_LEN,
    );
    key.extend_from_slice(VAULT_LFS_REF_KEY_PREFIX);
    key.extend_from_slice(repo_id.as_bytes());
    key.push(LFS_REF_KEY_SEPARATOR);
    key.extend_from_slice(ref_name.as_bytes());
    key.push(LFS_REF_KEY_SEPARATOR);
    key
}

fn lfs_ref_key(repo_id: &EntityId, ref_name: &str, oid: &LfsOid) -> Vec<u8> {
    let mut key = lfs_ref_prefix(repo_id, ref_name);
    key.extend_from_slice(oid.as_bytes());
    key
}

pub(super) fn encode_lfs_object_record(object: &VaultLfsObject) -> [u8; LFS_OBJECT_RECORD_LEN] {
    let mut value = [0_u8; LFS_OBJECT_RECORD_LEN];
    value[..ENTITY_ID_LEN].copy_from_slice(object.asset_id.as_bytes());
    value[ENTITY_ID_LEN..ENTITY_ID_LEN + 8].copy_from_slice(&object.size_bytes.to_le_bytes());
    value[ENTITY_ID_LEN + 8..ENTITY_ID_LEN + 16].copy_from_slice(&object.created_at.to_le_bytes());
    value[ENTITY_ID_LEN + 16..].copy_from_slice(object.ref_owner.as_bytes());
    value
}

pub(super) fn decode_lfs_object_record(oid: LfsOid, raw: &[u8]) -> Result<VaultLfsObject> {
    if raw.len() != LFS_OBJECT_RECORD_LEN {
        return Err(Error::CorruptedIndex("vault lfs object record"));
    }
    let mut id = [0_u8; ENTITY_ID_LEN];
    id.copy_from_slice(&raw[..ENTITY_ID_LEN]);
    let mut size = [0_u8; 8];
    size.copy_from_slice(&raw[ENTITY_ID_LEN..ENTITY_ID_LEN + 8]);
    let mut created = [0_u8; 8];
    created.copy_from_slice(&raw[ENTITY_ID_LEN + 8..ENTITY_ID_LEN + 16]);
    let owner = raw[ENTITY_ID_LEN + 16..]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("lfs ref owner"))?;
    Ok(VaultLfsObject {
        oid,
        asset_id: EntityId::from_bytes(id)
            .map_err(|_| Error::CorruptedIndex("vault lfs object asset id"))?,
        size_bytes: u64::from_le_bytes(size),
        created_at: u64::from_le_bytes(created),
        ref_owner: EntityId::from_bytes(owner)
            .map_err(|_| Error::CorruptedIndex("lfs ref owner"))?,
    })
}
