//! Moved from `crates/oneiron/src/origin/lfs/chunks.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::origin::lfs::store::VAULT_LFS_ASSET_ID_DOMAIN;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::origin::lfs::chunks::*;

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
        oneiron_store::code_snapshot::ids::entity_id_from_hash_material(
            VAULT_LFS_ASSET_ID_DOMAIN,
            &[&self.hash()?],
        )
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
