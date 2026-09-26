//! Object plane: Vault adapter methods, shared expectation gate, key builders, record codec.

use super::{
    LfsAdmission, LfsAssetClass, LfsOid, LfsPathPolicy, LfsPointerIntent, VAULT_LFS_OID_LEN,
};
use crate::Vault;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::temporal::TimeRange;

/// Schema version of both `vault_meta` row families below.
pub const VAULT_LFS_SCHEMA_VERSION: u8 = 2;

/// Domain separator for deterministic LFS ASSET ids.
pub const VAULT_LFS_ASSET_ID_DOMAIN: &[u8] = b"oneiron:origin-lfs-asset:v1";

/// Domain separator for the repository key an attachment row is scoped to.
pub const VAULT_LFS_REPO_ID_DOMAIN: &[u8] = b"oneiron:origin-lfs-repo:v1";

/// The one Git-LFS transfer adapter this origin serves.
pub const LFS_BASIC_TRANSFER: &str = "basic";

/// The Git-LFS batch API media type.
pub const LFS_JSON_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// `asset_id(16) ++ size u64 LE(8) ++ created_at u64 LE(8) ++ ref_owner(16)`.
const LFS_OBJECT_RECORD_LEN: usize = ENTITY_ID_LEN * 2 + 16;

/// Durable LFS object record: asset id, size, created time, ref owner. Key: oid.
pub(super) const OBJECTS: SideTable<LfsOid, LfsObjectRecord, Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_OBJECT);

/// Attaches one LFS object id to one git ref in one repository (value = learned_at u64 LE). Key:
/// repo id "\x00" ref_name "\x00" oid. A git ref name can never carry a NUL, so the fields stay
/// unambiguously framed.
pub(super) const REFS: SideTable<LfsRefKey, [u8; 8], Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_REF);

/// `origin:lfs:ref:v1:` key shape: repo id, then a NUL-framed ref name, then the OID.
pub(super) struct LfsRefKey {
    pub(super) repo_id: EntityId,
    ref_name: String,
    pub(super) oid: LfsOid,
}

impl SideKey for LfsRefKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.repo_id.encode_into(out);
        out.push(0);
        out.extend_from_slice(self.ref_name.as_bytes());
        out.push(0);
        self.oid.encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (repo_bytes, rest) = bytes.split_at_checked(ENTITY_ID_LEN)?;
        let (&separator, rest) = rest.split_first()?;
        if separator != 0 {
            return None;
        }
        let oid_start = rest.len().checked_sub(VAULT_LFS_OID_LEN)?;
        let (name_and_sep, oid_bytes) = rest.split_at(oid_start);
        let (&separator, name_bytes) = name_and_sep.split_last()?;
        if separator != 0 {
            return None;
        }
        Some(Self {
            repo_id: EntityId::from_bytes(repo_bytes.try_into().ok()?).ok()?,
            ref_name: String::from_utf8(name_bytes.to_vec()).ok()?,
            oid: LfsOid::decode_key(oid_bytes)?,
        })
    }
}

/// The bytes after `REFS`'s prefix that name every row for one repo+ref, without the trailing
/// OID.
fn ref_scan_prefix(repo_id: &EntityId, ref_name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTITY_ID_LEN + ref_name.len() + 2);
    out.extend_from_slice(repo_id.as_bytes());
    out.push(0);
    out.extend_from_slice(ref_name.as_bytes());
    out.push(0);
    out
}

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
        if super::lifecycle::DELETED.contains(&self.store, &txn, &oid)? {
            return Ok(None);
        }
        Ok(OBJECTS
            .get(&self.store, &txn, &oid)?
            .map(|record| record.with_oid(oid)))
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
        let key = LfsRefKey {
            repo_id,
            ref_name: ref_name.to_owned(),
            oid,
        };
        self.with_write_txn(|wtxn| {
            if super::lifecycle::DELETED.contains(&self.store, wtxn, &oid)?
                || !OBJECTS.contains(&self.store, wtxn, &oid)?
            {
                return Err(super::chunks::invalid(
                    "cannot attach missing or deleted lfs object",
                ));
            }
            REFS.put(&self.store, wtxn, &key, &learned_at.to_le_bytes())?;
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
        let prefix = ref_scan_prefix(&repo_id, ref_name);
        self.with_write_txn(|wtxn| {
            let keys = REFS.scan_keys(&self.store, wtxn, &prefix)?;
            let removed = u64::try_from(keys.len())
                .map_err(|_| Error::ArithmeticOverflow("lfs ref row count exceeds u64"))?;
            for key in &keys {
                REFS.delete(&self.store, wtxn, key)?;
            }
            Ok(removed)
        })
    }

    /// The object ids one git ref currently references.
    pub fn lfs_git_ref_objects(&self, repo_id: EntityId, ref_name: &str) -> Result<Vec<LfsOid>> {
        let prefix = ref_scan_prefix(&repo_id, ref_name);
        let rtxn = self.store.env.read_txn()?;
        let mut oids = Vec::new();
        for key in REFS.scan_keys(&self.store, &rtxn, &prefix)? {
            if !super::lifecycle::DELETED.contains(&self.store, &rtxn, &key.oid)? {
                oids.push(key.oid);
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

/// The `ORIGIN_LFS_OBJECT` value half of a [`VaultLfsObject`] row: everything except the oid,
/// which is the row's own key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LfsObjectRecord {
    asset_id: EntityId,
    size_bytes: u64,
    created_at: u64,
    pub(super) ref_owner: EntityId,
}

impl LfsObjectRecord {
    pub(super) fn from_object(object: &VaultLfsObject) -> Self {
        Self {
            asset_id: object.asset_id,
            size_bytes: object.size_bytes,
            created_at: object.created_at,
            ref_owner: object.ref_owner,
        }
    }

    pub(super) fn with_oid(self, oid: LfsOid) -> VaultLfsObject {
        VaultLfsObject {
            oid,
            asset_id: self.asset_id,
            size_bytes: self.size_bytes,
            created_at: self.created_at,
            ref_owner: self.ref_owner,
        }
    }
}

/// `asset_id(16) ++ size u64 LE(8) ++ created_at u64 LE(8) ++ ref_owner(16)`, unchanged.
impl RawValue for LfsObjectRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = [0_u8; LFS_OBJECT_RECORD_LEN];
        value[..ENTITY_ID_LEN].copy_from_slice(self.asset_id.as_bytes());
        value[ENTITY_ID_LEN..ENTITY_ID_LEN + 8].copy_from_slice(&self.size_bytes.to_le_bytes());
        value[ENTITY_ID_LEN + 8..ENTITY_ID_LEN + 16]
            .copy_from_slice(&self.created_at.to_le_bytes());
        value[ENTITY_ID_LEN + 16..].copy_from_slice(self.ref_owner.as_bytes());
        Ok(value.to_vec())
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        if raw.len() != LFS_OBJECT_RECORD_LEN {
            return Err(Error::CorruptedIndex("vault lfs object record").into());
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
        Ok(Self {
            asset_id: EntityId::from_bytes(id)
                .map_err(|_| Error::CorruptedIndex("vault lfs object asset id"))?,
            size_bytes: u64::from_le_bytes(size),
            created_at: u64::from_le_bytes(created),
            ref_owner: EntityId::from_bytes(owner)
                .map_err(|_| Error::CorruptedIndex("lfs ref owner"))?,
        })
    }
}
