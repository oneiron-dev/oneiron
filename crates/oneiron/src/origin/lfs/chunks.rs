//! Canonical BLAKE3 chunk manifests and vault-private FastCDC parameters.

use super::store::VAULT_LFS_ASSET_ID_DOMAIN;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::{EntityId, Vault};
use rand_core::{OsRng, RngCore};

/// Minimum FastCDC chunk size (the final chunk may be shorter).
pub const LFS_CHUNK_MIN: usize = 32 * 1024;
/// Target FastCDC chunk size.
pub const LFS_CHUNK_AVG: usize = 64 * 1024;
/// Maximum FastCDC chunk size.
pub const LFS_CHUNK_MAX: usize = 128 * 1024;
const PARAM_KEY: &[u8] = b"origin:lfs:cdc:v1";
const MANIFEST_MAGIC: &[u8; 8] = b"LFSCDC01";
pub(super) const CHUNK_DOMAIN: &[u8] = b"oneiron:origin-lfs-chunk:v1";
pub(super) const CHUNK_MARK: &[u8] = b"origin:lfs:chunk:v1:";
pub(super) const OWNER_REF: &[u8] = b"origin:lfs:owner-ref:v1:";
pub(super) const REF_PREFIX: &[u8] = b"origin:lfs:chunk-ref:v1:";

/// Persisted vault-specific boundary randomization, never sent to another vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LfsChunkParameters {
    /// Random gear-table seed. Boundaries remain stable within this vault.
    pub seed: u64,
}

/// One ordered reference in a manifest. The id hashes the raw chunk bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LfsChunkRef {
    /// BLAKE3 of the chunk body.
    pub hash: [u8; 32],
    /// Exact body length, never larger than 128 KiB.
    pub size: u32,
}

/// A canonical content-addressed object manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LfsManifest {
    /// Sum of the ordered chunk lengths.
    pub size_bytes: u64,
    /// Ordered chunks, including repeated occurrences.
    pub chunks: Vec<LfsChunkRef>,
}

impl LfsManifest {
    /// Canonical binary representation used for the BLAKE3 manifest id.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let count = u32::try_from(self.chunks.len()).map_err(|_| invalid("too many lfs chunks"))?;
        let mut out = Vec::with_capacity(20 + self.chunks.len() * 36);
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&self.size_bytes.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.hash);
            out.extend_from_slice(&chunk.size.to_le_bytes());
        }
        Ok(out)
    }

    /// Strict decoding; rejects inconsistent sizes and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 20 || &bytes[..8] != MANIFEST_MAGIC {
            return Err(invalid("invalid lfs manifest header"));
        }
        let size_bytes = u64::from_le_bytes(bytes[8..16].try_into().expect("length checked"));
        let count = u32::from_le_bytes(bytes[16..20].try_into().expect("length checked")) as usize;
        if count.checked_mul(36).and_then(|n| n.checked_add(20)) != Some(bytes.len()) {
            return Err(invalid("invalid lfs manifest length"));
        }
        let chunks = bytes[20..]
            .chunks_exact(36)
            .map(|entry| LfsChunkRef {
                hash: entry[..32].try_into().expect("entry length"),
                size: u32::from_le_bytes(entry[32..].try_into().expect("entry length")),
            })
            .collect();
        let manifest = Self { size_bytes, chunks };
        manifest.validate()?;
        Ok(manifest)
    }

    /// BLAKE3 of the canonical manifest bytes, not the Git-LFS SHA-256 pointer.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    /// The ordinary ASSET that stores this manifest.
    pub fn asset_id(&self) -> Result<EntityId> {
        crate::codebase::entity_id_from_hash_material(VAULT_LFS_ASSET_ID_DOMAIN, &[&self.hash()?])
    }

    fn validate(&self) -> Result<()> {
        let mut sum = 0u64;
        for chunk in &self.chunks {
            if chunk.size == 0 || chunk.size as usize > LFS_CHUNK_MAX {
                return Err(invalid("invalid lfs chunk length"));
            }
            sum = sum
                .checked_add(u64::from(chunk.size))
                .ok_or_else(|| invalid("lfs size overflow"))?;
        }
        if sum != self.size_bytes {
            return Err(invalid("lfs manifest size mismatch"));
        }
        Ok(())
    }
}

impl Vault {
    /// Returns this vault's durable boundary parameters, minting once.
    pub fn lfs_chunk_parameters(&self) -> Result<LfsChunkParameters> {
        self.with_write_txn(|txn| {
            let seed = if let Some(raw) = self.store.vault_meta.get(txn, PARAM_KEY)? {
                u64::from_le_bytes(
                    raw.as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("lfs cdc seed"))?,
                )
            } else {
                let mut seed = OsRng.next_u64();
                while seed == 0 {
                    seed = OsRng.next_u64();
                }
                self.store
                    .vault_meta
                    .put(txn, PARAM_KEY, &seed.to_le_bytes())?;
                seed
            };
            if seed == 0 {
                return Err(Error::CorruptedIndex("lfs cdc zero seed"));
            }
            Ok(LfsChunkParameters { seed })
        })
    }

    /// Reads and authenticates the manifest before exposing its references.
    pub fn lfs_manifest(&self, oid: super::LfsOid) -> Result<Option<LfsManifest>> {
        let Some(object) = self.lfs_object(oid)? else {
            return Ok(None);
        };
        let body = asset_body(self, &object.asset_id)?;
        let manifest =
            LfsManifest::decode(&body).map_err(|_| Error::CorruptedIndex("lfs manifest"))?;
        if manifest.asset_id()? != object.asset_id || manifest.size_bytes != object.size_bytes {
            return Err(Error::CorruptedIndex("lfs manifest digest"));
        }
        Ok(Some(manifest))
    }

    /// Reads one verified chunk belonging to this live object, never an arbitrary vault hash.
    pub fn lfs_object_chunk(&self, oid: super::LfsOid, hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let Some(manifest) = self.lfs_manifest(oid)? else {
            return Ok(None);
        };
        let Some(chunk) = manifest.chunks.iter().find(|c| c.hash == hash) else {
            return Ok(None);
        };
        read_chunk(self, chunk).map(Some)
    }
}

pub(super) fn invalid(why: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(why))
}
pub(super) fn key(prefix: &[u8], tail: &[u8]) -> Vec<u8> {
    [prefix, tail].concat()
}
pub(super) fn chunk_id(hash: &[u8; 32]) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(CHUNK_DOMAIN, &[hash])
}
pub(super) fn ref_key(hash: &[u8; 32], owner: EntityId) -> Vec<u8> {
    [REF_PREFIX, hash.as_slice(), owner.as_bytes().as_slice()].concat()
}
pub(super) fn asset_body(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let raw = vault
        .get_raw(id)?
        .ok_or(Error::CorruptedIndex("missing lfs asset"))?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("lfs asset header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::CorruptedIndex("lfs asset type"));
    }
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}
pub(super) fn read_chunk(vault: &Vault, chunk: &LfsChunkRef) -> Result<Vec<u8>> {
    let bytes = asset_body(vault, &chunk_id(&chunk.hash)?)?;
    if bytes.len() != chunk.size as usize || blake3::hash(&bytes).as_bytes() != &chunk.hash {
        return Err(Error::CorruptedIndex("lfs chunk digest"));
    }
    Ok(bytes)
}

pub(super) fn owner_ref_key(owner: EntityId, hash: &[u8; 32]) -> Vec<u8> {
    [OWNER_REF, owner.as_bytes().as_slice(), hash.as_slice()].concat()
}

#[cfg(feature = "sync")]
impl Vault {
    pub(crate) fn lfs_chunk_if_present(&self, chunk: &LfsChunkRef) -> Result<Option<Vec<u8>>> {
        if self.get_raw(&chunk_id(&chunk.hash)?)?.is_none() {
            return Ok(None);
        }
        read_chunk(self, chunk).map(Some)
    }
}
