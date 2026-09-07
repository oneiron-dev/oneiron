//! Vault-LFS: the Git-LFS object plane over the vault's EXISTING ASSET byte
//! plane (ARCH-0068 RA1, ONE-1909).
//!
//! The vault is the origin of git bytes. This module is the second concrete
//! bytes-in/bytes-out adapter beside [`super::smart_http`], and it deliberately
//! mints nothing new to be one:
//!
//! * every LFS byte is an ordinary [`ENTITY_TYPE_ASSET`] entity, so the
//!   standing batch pipeline — credential scan included — runs over it;
//! * the whole object plane is two ADDITIVE `vault_meta` prefix row families
//!   ([`VAULT_LFS_OBJECT_KEY_PREFIX`], [`VAULT_LFS_REF_KEY_PREFIX`]). No new
//!   entity type byte, no new named database, no new public storage primitive,
//!   no dependency;
//! * asset ids are deterministic through [`entity_id_from_hash_material`] over
//!   an LFS-only domain, so an LFS asset id can never collide with a
//!   blob-artifact or codebase asset id even for byte-identical content.
//!
//! # The two hash families coexist
//!
//! SHA-256 is the Git-LFS object id and therefore the dedup key HERE. BLAKE3
//! stays the frozen [`crate::blob_artifact::BlobArtifactVersion`] contract
//! THERE. Neither rewrites the other: they are different domains over different
//! prefixes, and this module never touches a `blob_artifact:` row.
//!
//! # Dedup is vault-scoped
//!
//! A vault is one tenant's sealed store. An object id computed from one
//! tenant's bytes never resolves storage for another, exactly as the
//! blob-artifact store already holds it.
//!
//! # Read paths fail closed
//!
//! [`Vault::get_lfs_object`] and [`Vault::verify_lfs_object`] re-check the
//! stored length AND re-hash the stored body before either answers. A body that
//! disagrees with its record is [`Error::CorruptedIndex`], never `Ok(bytes)` —
//! wrong bytes are not a successful download.
//!
//! # Admission is policy, never a size threshold
//!
//! [`LfsPathPolicy`] classifies a repository path; [`Vault::admit_lfs_pointer`]
//! turns that classification into an [`LfsAdmission`] and nothing else. The
//! caller enforces the outcome. There is NO automatic size threshold anywhere
//! in this module, and none may be added: a build-required asset is
//! build-required because of what it is, not because of how large it is.
//!
//! # What this module deliberately does not do
//!
//! No chunking (FastCDC stays deferred until measured duplication justifies
//! it). No transport: the HTTP surface lives in the server crate and calls
//! these entry points. No credential handling and no token format.

use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;

/// Schema version of both `vault_meta` row families below.
pub const VAULT_LFS_SCHEMA_VERSION: u8 = 1;

/// Raw byte length of a Git-LFS object id (SHA-256).
pub const VAULT_LFS_OID_LEN: usize = 32;

/// Hex-encoded length of a Git-LFS object id.
pub const VAULT_LFS_OID_HEX_LEN: usize = 64;

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

/// The `oid sha256:` field of a Git-LFS pointer file.
const LFS_POINTER_OID_FIELD: &str = "oid sha256:";

/// The `size ` field of a Git-LFS pointer file.
const LFS_POINTER_SIZE_FIELD: &str = "size ";

/// The `version ` field of a Git-LFS pointer file.
const LFS_POINTER_VERSION_FIELD: &str = "version ";

/// The optional `ext-N-<name> ` field family of a Git-LFS pointer file.
const LFS_POINTER_EXT_FIELD: &str = "ext-";

/// `asset_id(16) ++ size u64 LE(8) ++ created_at u64 LE(8)`.
const LFS_OBJECT_RECORD_LEN: usize = ENTITY_ID_LEN + 16;

/// The key separator inside an attachment key. A git ref name can never carry
/// a NUL, so the repo_id/ref_name/OID fields stay unambiguously framed.
const LFS_REF_KEY_SEPARATOR: u8 = 0;

// ---------------------------------------------------------------------------
// The object id
// ---------------------------------------------------------------------------

/// A Git-LFS object id: the SHA-256 of the object's bytes.
///
/// Deliberately a distinct 32-byte type from the 16-byte [`EntityId`]: an
/// object id addresses BYTES and an entity id addresses an ENTITY, and the two
/// are never interchangeable even though one deterministically derives the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LfsOid([u8; VAULT_LFS_OID_LEN]);

impl LfsOid {
    /// Wraps raw object-id bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VAULT_LFS_OID_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses the 64-character lowercase-or-uppercase hex spelling.
    ///
    /// Rejects any other length and any non-hex character; there is no lenient
    /// path, because a mis-parsed object id would address the wrong bytes.
    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != VAULT_LFS_OID_HEX_LEN {
            return Err(Error::InvalidLfsObject(
                "lfs oid must be 64 hex characters",
            ));
        }
        let mut bytes = [0_u8; VAULT_LFS_OID_LEN];
        for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            *slot = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// The SHA-256 of `bytes` — the first and only hash of an LFS body.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut oid = [0_u8; VAULT_LFS_OID_LEN];
        oid.copy_from_slice(&digest);
        Self(oid)
    }

    /// The raw object-id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VAULT_LFS_OID_LEN] {
        &self.0
    }

    /// The 64-character lowercase hex spelling clients send on the wire.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut hex = String::with_capacity(VAULT_LFS_OID_HEX_LEN);
        for byte in self.0 {
            hex.push(hex_digit(byte >> 4));
            hex.push(hex_digit(byte & 0x0f));
        }
        hex
    }
}

const fn hex_digit(nibble: u8) -> char {
    (if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }) as char
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidLfsObject("lfs oid is not hex")),
    }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// What a repository path's bytes ARE, which is what decides where they live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LfsAssetClass {
    /// A large asset the repository carries: it belongs in the LFS plane.
    RepositoryLarge,
    /// An asset a build produces or consumes: it stays ordinary Git content.
    BuildRequired,
}

impl LfsAssetClass {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryLarge => "repository-large",
            Self::BuildRequired => "build-required",
        }
    }
}

/// What the caller must do with one pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LfsAdmission {
    /// The pointer's bytes belong in the LFS plane, and the pointer publishes
    /// only once those bytes are present.
    StoreInLfs,
    /// The pointer stays ordinary Git content: no LFS publication, and no
    /// durable ref attachment.
    KeepInGit,
}

impl LfsAdmission {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreInLfs => "store-in-lfs",
            Self::KeepInGit => "keep-in-git",
        }
    }
}

/// The classification seam.
///
/// A path is classified by WHAT IT IS. Implementations must never consult a
/// byte count: a size threshold would silently reclassify a build input the
/// day it grew, which is exactly the failure this seam exists to prevent.
pub trait LfsPathPolicy: Send + Sync {
    /// Classifies one repository path within one repository.
    fn classify(&self, repo_id: EntityId, path: &str) -> Result<LfsAssetClass>;
}

/// The v1 default: every path is [`LfsAssetClass::RepositoryLarge`].
///
/// A configuration-driven classifier belongs to the ticket that makes the
/// server configuration a claimed file; until then the honest default is the
/// one that stores what a push declared as LFS and refuses to guess.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRepositoryLargeLfsPathPolicy;

impl LfsPathPolicy for DefaultRepositoryLargeLfsPathPolicy {
    fn classify(&self, _repo_id: EntityId, _path: &str) -> Result<LfsAssetClass> {
        Ok(LfsAssetClass::RepositoryLarge)
    }
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

/// One LFS pointer, paired with the repository path that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsPointerIntent {
    /// The repository the pointer landed in.
    pub repo_id: EntityId,
    /// The repository-relative path of the pointer file.
    pub path: String,
    /// The object id the pointer names.
    pub oid: LfsOid,
    /// The byte length the pointer declares.
    pub size_bytes: u64,
}

/// One LFS pointer a push introduced, before it is scoped to a repository.
///
/// The wire-side pairing (path ↔ pointer) is knowable at the door, where the
/// pushed blobs are still framed; the repository key is knowable only at the
/// landing, where the object store's identity has been proven. This type
/// carries the first half so the second half is added exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsPushedPointer {
    /// The repository-relative path of the pointer file.
    pub path: String,
    /// The object id the pointer names.
    pub oid: LfsOid,
    /// The byte length the pointer declares.
    pub size_bytes: u64,
}

impl LfsPushedPointer {
    /// Reads a Git-LFS pointer out of the lines a push ADDED to one blob.
    ///
    /// Every added line must be a pointer field, and `oid`/`size` must both be
    /// present and well formed. That conjunction is what keeps an ordinary
    /// source file that happens to mention a SHA-256 from being mistaken for a
    /// pointer: a pointer file is pointer fields and nothing else, so any line
    /// outside the grammar disqualifies the whole blob.
    ///
    /// Reading the ADDED lines (rather than requiring a `version` line) is what
    /// makes a pointer MODIFICATION visible: retargeting a pointer changes
    /// `oid` and `size` while `version` stays context.
    #[must_use]
    pub fn from_pointer_lines(path: &str, added_lines: &[Vec<u8>]) -> Option<Self> {
        let mut oid = None;
        let mut size_bytes = None;
        let mut fields = 0_usize;
        for line in added_lines {
            let line = std::str::from_utf8(line).ok()?;
            if line.is_empty() {
                continue;
            }
            fields += 1;
            if let Some(value) = line.strip_prefix(LFS_POINTER_OID_FIELD) {
                oid = Some(LfsOid::parse_hex(value).ok()?);
            } else if let Some(value) = line.strip_prefix(LFS_POINTER_SIZE_FIELD) {
                size_bytes = Some(value.parse::<u64>().ok()?);
            } else if !line.starts_with(LFS_POINTER_VERSION_FIELD)
                && !line.starts_with(LFS_POINTER_EXT_FIELD)
            {
                return None;
            }
        }
        if fields == 0 {
            return None;
        }
        Some(Self {
            path: path.to_owned(),
            oid: oid?,
            size_bytes: size_bytes?,
        })
    }

    /// Scopes this pointer to one repository.
    #[must_use]
    pub fn intent(&self, repo_id: EntityId) -> LfsPointerIntent {
        LfsPointerIntent {
            repo_id,
            path: self.path.clone(),
            oid: self.oid,
            size_bytes: self.size_bytes,
        }
    }
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
        return Err(Error::InvalidLfsObject(
            "declared lfs size does not match the body length",
        ));
    }
    if LfsOid::digest(bytes) != expected_oid {
        return Err(Error::InvalidLfsObject(
            "body sha256 does not match the declared lfs oid",
        ));
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

fn lfs_asset_entity_id(oid: &LfsOid) -> Result<EntityId> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::test_util::{embedding_test_config, open_test_vault_with};

    const LEARNED_AT: u64 = 1_700_000_000;

    fn test_time() -> TimeRange {
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        }
    }

    fn repo_id() -> EntityId {
        lfs_repo_id("a".repeat(64).as_str()).expect("repo id")
    }

    fn pointer_lines(oid: LfsOid, size: u64) -> Vec<Vec<u8>> {
        vec![
            b"version https://git-lfs.github.com/spec/v1".to_vec(),
            format!("oid sha256:{}", oid.to_hex()).into_bytes(),
            format!("size {size}").into_bytes(),
        ]
    }

    /// Replaces one ASSET entity's stored bytes THROUGH the raw store, which is
    /// what real corruption looks like: no write path validated it, and the
    /// lookup row still claims the original digest and length.
    fn overwrite_stored_bytes(vault: &Vault, asset_id: EntityId, body: &[u8]) {
        let payload =
            crate::test_util::entity_record(ENTITY_TYPE_ASSET, test_time(), LEARNED_AT, body);
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .put(wtxn, asset_id.as_bytes(), &payload)?;
                Ok(())
            })
            .expect("overwrite stored asset bytes");
    }

    /// A policy that answers one fixed class, so an admission row proves the
    /// mapping and not the default.
    struct FixedPolicy(LfsAssetClass);

    impl LfsPathPolicy for FixedPolicy {
        fn classify(&self, _repo_id: EntityId, _path: &str) -> Result<LfsAssetClass> {
            Ok(self.0)
        }
    }

    #[test]
    fn lfs_oid_digest_matches_sha256() {
        let bytes = b"vault lfs object bytes";
        let expected = Sha256::digest(bytes);
        let oid = LfsOid::digest(bytes);
        assert_eq!(
            oid.as_bytes().as_slice(),
            AsRef::<[u8]>::as_ref(&expected),
            "digest is plain SHA-256"
        );

        let hex = oid.to_hex();
        assert_eq!(hex.len(), VAULT_LFS_OID_HEX_LEN);
        assert!(
            hex.chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
            "to_hex is 64 lowercase hex characters"
        );
        assert_eq!(LfsOid::parse_hex(&hex).expect("round trip"), oid);
        assert_eq!(
            LfsOid::parse_hex(&hex.to_uppercase()).expect("uppercase parses"),
            oid
        );

        assert_eq!(
            LfsOid::parse_hex(&hex[..VAULT_LFS_OID_HEX_LEN - 1])
                .expect_err("short oid is refused")
                .kind(),
            ErrorKind::InvalidLfsObject
        );
        let mut non_hex = hex;
        non_hex.replace_range(0..1, "z");
        assert_eq!(
            LfsOid::parse_hex(&non_hex)
                .expect_err("non-hex oid is refused")
                .kind(),
            ErrorKind::InvalidLfsObject
        );
    }

    #[test]
    fn lfs_put_writes_asset_and_lookup_row_once() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"one upload writes one object".to_vec();
        let oid = LfsOid::digest(&bytes);

        let outcome = vault
            .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
            .expect("first upload");
        assert!(!outcome.deduplicated, "the first upload stores bytes");
        assert_eq!(outcome.object.oid, oid);
        assert_eq!(
            outcome.object.size_bytes,
            u64::try_from(bytes.len()).expect("length fits u64")
        );
        assert_eq!(outcome.object.created_at, LEARNED_AT);
        assert_eq!(
            outcome.object.asset_id,
            lfs_asset_entity_id(&oid).expect("deterministic asset id"),
            "the asset id is derived from the oid under the LFS domain"
        );

        let record = vault.lfs_object(oid).expect("record read").expect("record");
        assert_eq!(record, outcome.object, "the row carries the whole record");
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_ASSET)
                .expect("scan assets"),
            vec![record.asset_id],
            "exactly one ASSET entity exists, and it is this object's"
        );
        assert_eq!(
            vault.get(&record.asset_id).expect("asset read"),
            Some(bytes.clone()),
            "the bytes are an ordinary ASSET entity"
        );
        assert_eq!(
            vault.get_lfs_object(oid).expect("download"),
            Some(bytes),
            "the object reads back byte-exact"
        );
    }

    #[test]
    fn lfs_put_rejects_expected_oid_mismatch_without_writing() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"the bytes that were actually sent".to_vec();
        let claimed = LfsOid::digest(b"different bytes entirely");

        let refused = vault
            .put_lfs_object(claimed, &bytes, test_time(), LEARNED_AT)
            .expect_err("a body that is not the declared oid is refused");
        assert_eq!(refused.kind(), ErrorKind::InvalidLfsObject);

        assert_eq!(
            vault.lfs_object(claimed).expect("record read"),
            None,
            "no lookup row exists after the refusal"
        );
        assert!(
            vault
                .entities_by_type(ENTITY_TYPE_ASSET)
                .expect("scan assets")
                .is_empty(),
            "no ASSET entity exists after the refusal"
        );
        assert_eq!(
            vault
                .lfs_object(LfsOid::digest(&bytes))
                .expect("record read"),
            None,
            "and the real digest was not stored either"
        );
    }

    #[test]
    fn lfs_put_rejects_size_mismatch_without_writing() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"twenty nine bytes of body ok!".to_vec();
        let oid = LfsOid::digest(&bytes);
        let declared = u64::try_from(bytes.len()).expect("length fits u64") + 1;

        // The shared gate the HTTP upload route runs before it ever calls the
        // engine: a declared size that disagrees with the body fails here.
        let refused = check_lfs_expectation(oid, Some(declared), &bytes)
            .expect_err("a declared size that disagrees is refused");
        assert_eq!(refused.kind(), ErrorKind::InvalidLfsObject);
        assert!(
            check_lfs_expectation(
                oid,
                Some(u64::try_from(bytes.len()).expect("length fits u64")),
                &bytes
            )
            .is_ok(),
            "the agreeing size passes the same gate"
        );

        assert_eq!(
            vault.lfs_object(oid).expect("record read"),
            None,
            "the refusal happened before any write"
        );
        assert!(
            vault
                .entities_by_type(ENTITY_TYPE_ASSET)
                .expect("scan assets")
                .is_empty(),
            "and no ASSET entity was created"
        );
    }

    #[test]
    fn lfs_put_dedup_second_upload_is_one_object() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"identical bytes uploaded twice".to_vec();
        let oid = LfsOid::digest(&bytes);

        let first = vault
            .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
            .expect("first upload");
        let second = vault
            .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT + 60)
            .expect("second upload");

        assert!(!first.deduplicated);
        assert!(second.deduplicated, "the second upload stores nothing");
        assert_eq!(first.object, second.object, "one durable record survives");
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_ASSET)
                .expect("scan assets"),
            vec![first.object.asset_id],
            "two identical uploads are one ASSET entity"
        );
        assert_eq!(
            second.object.created_at, LEARNED_AT,
            "the record keeps its original first-seen stamp"
        );
        assert_eq!(
            vault.get_lfs_object(oid).expect("download"),
            Some(bytes),
            "and the bytes are still exactly the uploaded bytes"
        );
    }

    #[test]
    fn lfs_get_and_verify_fail_closed_on_corrupt_body() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"bytes that will be tampered with".to_vec();
        let size = u64::try_from(bytes.len()).expect("length fits u64");
        let oid = LfsOid::digest(&bytes);
        let record = vault
            .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
            .expect("upload")
            .object;
        assert!(vault.verify_lfs_object(oid, size).expect("verify"));

        // Same length, one flipped byte: only a re-hash can catch this.
        let mut flipped = bytes.clone();
        flipped[0] ^= 0xff;
        overwrite_stored_bytes(&vault, record.asset_id, &flipped);
        assert_eq!(
            vault
                .get_lfs_object(oid)
                .expect_err("a flipped body never reads back as success")
                .kind(),
            ErrorKind::CorruptedIndex
        );
        assert_eq!(
            vault
                .verify_lfs_object(oid, size)
                .expect_err("and verify refuses it too")
                .kind(),
            ErrorKind::CorruptedIndex
        );

        // Truncated: the length check catches it before the hash does.
        overwrite_stored_bytes(&vault, record.asset_id, &bytes[..bytes.len() - 1]);
        assert_eq!(
            vault
                .get_lfs_object(oid)
                .expect_err("a truncated body never reads back as success")
                .kind(),
            ErrorKind::CorruptedIndex
        );
        assert_eq!(
            vault
                .verify_lfs_object(oid, size)
                .expect_err("and verify refuses it too")
                .kind(),
            ErrorKind::CorruptedIndex
        );
    }

    #[test]
    fn lfs_attach_and_detach_ref_rows() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let bytes = b"bytes two refs both reference".to_vec();
        let oid = LfsOid::digest(&bytes);
        vault
            .put_lfs_object(oid, &bytes, test_time(), LEARNED_AT)
            .expect("upload");
        let repo = repo_id();

        vault
            .attach_lfs_object_to_git_ref(repo, "refs/heads/main", oid, LEARNED_AT)
            .expect("attach to main");
        vault
            .attach_lfs_object_to_git_ref(repo, "refs/heads/release", oid, LEARNED_AT)
            .expect("attach to release");
        assert_eq!(
            vault
                .lfs_git_ref_objects(repo, "refs/heads/main")
                .expect("read main rows"),
            vec![oid]
        );

        assert_eq!(
            vault
                .detach_lfs_objects_from_git_ref(repo, "refs/heads/main")
                .expect("detach main"),
            1,
            "detach reports the rows it removed"
        );
        assert!(
            vault
                .lfs_git_ref_objects(repo, "refs/heads/main")
                .expect("read main rows")
                .is_empty(),
            "that ref's rows are gone"
        );
        assert_eq!(
            vault
                .lfs_git_ref_objects(repo, "refs/heads/release")
                .expect("read release rows"),
            vec![oid],
            "another ref's attachment survives"
        );
        assert_eq!(
            vault.get_lfs_object(oid).expect("download"),
            Some(bytes),
            "and detaching never deletes shared bytes"
        );

        assert_eq!(
            vault
                .detach_lfs_objects_from_git_ref(repo, "refs/heads/release")
                .expect("detach release"),
            1
        );
        assert!(
            vault.lfs_object(oid).expect("record read").is_some(),
            "the object outlives its last attachment: this is not a collector"
        );
    }

    #[test]
    fn lfs_admission_build_required_returns_keep_in_git() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let repo = repo_id();
        let bytes = b"a build input that stays in git".to_vec();
        let oid = LfsOid::digest(&bytes);
        let size = u64::try_from(bytes.len()).expect("length fits u64");
        let pointer = LfsPushedPointer::from_pointer_lines(
            "tools/toolchain.tar.gz",
            &pointer_lines(oid, size),
        )
        .expect("a pointer file parses");
        let intent = pointer.intent(repo);

        assert_eq!(
            vault
                .admit_lfs_pointer(&FixedPolicy(LfsAssetClass::BuildRequired), &intent)
                .expect("classify"),
            LfsAdmission::KeepInGit
        );
        assert_eq!(LfsAssetClass::BuildRequired.as_str(), "build-required");
        assert_eq!(LfsAdmission::KeepInGit.as_str(), "keep-in-git");
        assert!(
            vault
                .lfs_git_ref_objects(repo, "refs/heads/main")
                .expect("read rows")
                .is_empty(),
            "classification alone never writes a durable ref attachment"
        );
    }

    #[test]
    fn lfs_admission_repository_large_returns_store_in_lfs() {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let repo = repo_id();
        // A one-byte body and a large declared size classify the SAME way:
        // there is no size threshold anywhere in this module.
        let small = LfsPushedPointer::from_pointer_lines(
            "assets/tiny.bin",
            &pointer_lines(LfsOid::digest(b"x"), 1),
        )
        .expect("pointer parses")
        .intent(repo);
        let large = LfsPushedPointer::from_pointer_lines(
            "assets/huge.bin",
            &pointer_lines(LfsOid::digest(b"y"), 8_000_000_000),
        )
        .expect("pointer parses")
        .intent(repo);

        let policy = DefaultRepositoryLargeLfsPathPolicy;
        for intent in [&small, &large] {
            assert_eq!(
                vault.admit_lfs_pointer(&policy, intent).expect("classify"),
                LfsAdmission::StoreInLfs
            );
        }
        assert_eq!(LfsAssetClass::RepositoryLarge.as_str(), "repository-large");
        assert_eq!(LfsAdmission::StoreInLfs.as_str(), "store-in-lfs");

        // The pointer grammar is a conjunction: ordinary content that merely
        // mentions an oid is not a pointer, and neither is a truncated one.
        assert!(
            LfsPushedPointer::from_pointer_lines(
                "src/main.rs",
                &[
                    format!("oid sha256:{}", LfsOid::digest(b"x").to_hex()).into_bytes(),
                    b"fn main() {}".to_vec(),
                ],
            )
            .is_none(),
            "a source file that mentions an oid is not a pointer"
        );
        assert!(
            LfsPushedPointer::from_pointer_lines(
                "assets/tiny.bin",
                &[b"version https://git-lfs.github.com/spec/v1".to_vec()],
            )
            .is_none(),
            "a pointer without oid and size is not a pointer"
        );
        assert_eq!(
            LfsPushedPointer::from_pointer_lines(
                "assets/tiny.bin",
                &[
                    format!("oid sha256:{}", LfsOid::digest(b"x").to_hex()).into_bytes(),
                    b"size 1".to_vec(),
                ],
            )
            .expect("a modified pointer parses from its changed fields alone")
            .size_bytes,
            1
        );
    }
}
