//! Canonical BLAKE3 chunk manifests and vault-private FastCDC parameters.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_ASSET;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use rand_core::{OsRng, RngCore};

/// Minimum FastCDC chunk size (the final chunk may be shorter).
pub const LFS_CHUNK_MIN: usize = 32 * 1024;
/// Target FastCDC chunk size.
pub const LFS_CHUNK_AVG: usize = 64 * 1024;
/// Maximum FastCDC chunk size.
pub const LFS_CHUNK_MAX: usize = 128 * 1024;

pub const MANIFEST_MAGIC: &[u8; 8] = b"LFSCDC01";
pub const CHUNK_DOMAIN: &[u8] = b"oneiron:origin-lfs-chunk:v1";

/// Generates the nonzero vault-private seed for the store's creation transaction.
/// The typed table cannot write until the vault's database manifest exists.
pub fn random_lfs_chunk_seed() -> [u8; 8] {
    let mut seed = OsRng.next_u64();
    while seed == 0 {
        seed = OsRng.next_u64();
    }
    seed.to_le_bytes()
}

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

pub fn invalid(why: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidLfsObject(why))
}
pub fn chunk_id(hash: &[u8; 32]) -> Result<EntityId> {
    crate::code_snapshot::ids::entity_id_from_hash_material(CHUNK_DOMAIN, &[hash])
}
pub fn checked_chunk(chunk: &LfsChunkRef, bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() != chunk.size as usize || blake3::hash(&bytes).as_bytes() != &chunk.hash {
        return Err(Error::CorruptedIndex("lfs chunk digest"));
    }
    Ok(bytes)
}
