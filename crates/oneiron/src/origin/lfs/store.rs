//! Object plane: Vault adapter methods, shared expectation gate, key builders, record codec.

use super::{
    LfsAdmission, LfsAssetClass, LfsOid, LfsPathPolicy, LfsPointerIntent, VAULT_LFS_OID_LEN,
};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;

/// Schema version of both `vault_meta` row families below.
pub const VAULT_LFS_SCHEMA_VERSION: u8 = 1;

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
const LFS_OBJECT_RECORD_LEN: usize = ENTITY_ID_LEN + 16;

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
    if let Some(expected_size) = expected_size
        && expected_size != actual_size
    {
        return Err(Error::Artifact(ArtifactError::InvalidLfsObject(
            "declared lfs size does not match the body length",
        )));
    }
    if LfsOid::digest(bytes) != expected_oid {
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

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------
impl Vault {
    /// Stores one LFS object, or recognizes bytes this vault already holds.
    ///
    /// Crate-local inherent impl in the feature module: `vault.rs` is never
    /// edited to add a feature's entry points (the blob-artifact precedent).
    ///
    /// The expectation check runs FIRST and outside the transaction, so a body
    /// that disagrees with its declared object id leaves no ASSET entity and no
    /// lookup row behind — the mismatch costs a hash, not a write.
    ///
    /// The bytes then enter the ordinary batch pipeline as an
    /// [`ENTITY_TYPE_ASSET`] put, which means the standing credential scan runs
    /// over them. That is deliberate and fail-closed: LFS is not a carve-out.
    pub fn put_lfs_object(
        &self,
        expected_oid: LfsOid,
        bytes: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<LfsPutOutcome> {
        check_lfs_expectation(expected_oid, None, bytes)?;
        let size_bytes = u64::try_from(bytes.len())
            .map_err(|_| Error::ArithmeticOverflow("lfs object length exceeds u64"))?;
        let key = lfs_object_key(&expected_oid);
        self.with_write_txn(|wtxn| {
            let existing = self
                .store
                .vault_meta
                .get(wtxn, &key)?
                .map(|raw| decode_lfs_object_record(expected_oid, &raw))
                .transpose()?;
            if let Some(object) = existing {
                // Byte-identical content is ONE object. The second upload
                // writes no ASSET entity and no second row.
                return Ok(LfsPutOutcome {
                    object,
                    deduplicated: true,
                });
            }
            let asset_id = lfs_asset_entity_id(&expected_oid)?;
            self.batch_in()
                .put(&asset_id, ENTITY_TYPE_ASSET, occurred, learned_at, bytes)
                .apply(wtxn)?;
            let object = VaultLfsObject {
                oid: expected_oid,
                asset_id,
                size_bytes,
                created_at: learned_at,
            };
            self.store
                .vault_meta
                .put(wtxn, &key, &encode_lfs_object_record(&object))?;
            Ok(LfsPutOutcome {
                object,
                deduplicated: false,
            })
        })
    }

    /// The durable record for one object id, without reading its bytes.
    pub fn lfs_object(&self, oid: LfsOid) -> Result<Option<VaultLfsObject>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, &lfs_object_key(&oid))? else {
            return Ok(None);
        };
        decode_lfs_object_record(oid, &raw).map(Some)
    }

    /// The publication gate primitive: are these exact bytes stored here?
    ///
    /// `Ok(true)` only when the row exists AND the stored length is the length
    /// the pointer declares. A pointer whose object is absent — or whose size
    /// disagrees with the stored object — is not publishable, because a ref
    /// that advertises it would fail checkout.
    pub fn has_lfs_object(&self, oid: LfsOid, expected_size: u64) -> Result<bool> {
        Ok(self
            .lfs_object(oid)?
            .is_some_and(|object| object.size_bytes == expected_size))
    }

    /// Reads one object's bytes, re-checking length AND digest on the way out.
    ///
    /// Fails closed: a stored body that disagrees with its record is
    /// [`Error::CorruptedIndex`], never `Ok(bytes)`. Serving the wrong bytes as
    /// a success is the one outcome an object store must never produce.
    pub fn get_lfs_object(&self, oid: LfsOid) -> Result<Option<Vec<u8>>> {
        let Some(record) = self.lfs_object(oid)? else {
            return Ok(None);
        };
        read_lfs_asset(self, &record).map(Some)
    }

    /// The verify verdict for one `(oid, size)` pair.
    ///
    /// `Ok(false)` means "this vault does not hold that object at that size" —
    /// an honest negative. Corruption of a body this vault DOES claim to hold
    /// is an error, not a `false`: the two facts are different and a client
    /// must be able to tell them apart.
    pub fn verify_lfs_object(&self, oid: LfsOid, expected_size: u64) -> Result<bool> {
        let Some(record) = self.lfs_object(oid)? else {
            return Ok(false);
        };
        if record.size_bytes != expected_size {
            return Ok(false);
        }
        read_lfs_asset(self, &record).map(|_| true)
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
            oids.push(LfsOid::from_bytes(raw));
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

/// Reads and re-verifies one record's ASSET body.
fn read_lfs_asset(vault: &Vault, record: &VaultLfsObject) -> Result<Vec<u8>> {
    let Some(raw) = vault.get_raw(&record.asset_id)? else {
        // The row asserts bytes this vault cannot produce. That is corruption,
        // not a miss: the miss is answered by the absent row.
        return Err(Error::CorruptedIndex("vault lfs object asset"));
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::CorruptedIndex("vault lfs object asset type"));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let stored_size = u64::try_from(body.len())
        .map_err(|_| Error::ArithmeticOverflow("lfs object length exceeds u64"))?;
    if stored_size != record.size_bytes {
        return Err(Error::CorruptedIndex("vault lfs object length"));
    }
    if LfsOid::digest(&body) != record.oid {
        return Err(Error::CorruptedIndex("vault lfs object bytes"));
    }
    Ok(body)
}

pub(super) fn lfs_asset_entity_id(oid: &LfsOid) -> Result<EntityId> {
    entity_id_from_hash_material(VAULT_LFS_ASSET_ID_DOMAIN, &[oid.as_bytes()])
}

fn lfs_object_key(oid: &LfsOid) -> Vec<u8> {
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

fn encode_lfs_object_record(object: &VaultLfsObject) -> [u8; LFS_OBJECT_RECORD_LEN] {
    let mut value = [0_u8; LFS_OBJECT_RECORD_LEN];
    value[..ENTITY_ID_LEN].copy_from_slice(object.asset_id.as_bytes());
    value[ENTITY_ID_LEN..ENTITY_ID_LEN + 8].copy_from_slice(&object.size_bytes.to_le_bytes());
    value[ENTITY_ID_LEN + 8..].copy_from_slice(&object.created_at.to_le_bytes());
    value
}

fn decode_lfs_object_record(oid: LfsOid, raw: &[u8]) -> Result<VaultLfsObject> {
    if raw.len() != LFS_OBJECT_RECORD_LEN {
        return Err(Error::CorruptedIndex("vault lfs object record"));
    }
    let mut id = [0_u8; ENTITY_ID_LEN];
    id.copy_from_slice(&raw[..ENTITY_ID_LEN]);
    let mut size = [0_u8; 8];
    size.copy_from_slice(&raw[ENTITY_ID_LEN..ENTITY_ID_LEN + 8]);
    let mut created = [0_u8; 8];
    created.copy_from_slice(&raw[ENTITY_ID_LEN + 8..]);
    Ok(VaultLfsObject {
        oid,
        asset_id: EntityId::from_bytes(id)
            .map_err(|_| Error::CorruptedIndex("vault lfs object asset id"))?,
        size_bytes: u64::from_le_bytes(size),
        created_at: u64::from_le_bytes(created),
    })
}
