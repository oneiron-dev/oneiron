//! Domain-separated entity identifiers for immutable snapshot assets and manifests.

use crate::code_snapshot::snapshot::CODEBASE_CONTENT_HASH_LEN;
use crate::code_snapshot::snapshot::CodebaseSnapshot;
use crate::code_snapshot::snapshot::write_hash_len;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;

const CODEBASE_ASSET_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";

const CODEBASE_SNAPSHOT_ID_DOMAIN: &[u8] = b"oneiron:codebase-snapshot-entity:v1";

pub fn codebase_asset_entity_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(CODEBASE_ASSET_ID_DOMAIN, &[content_hash])
}

pub fn codebase_snapshot_entity_id(snapshot: &CodebaseSnapshot) -> Result<EntityId> {
    entity_id_from_hash_material(
        CODEBASE_SNAPSHOT_ID_DOMAIN,
        &[&snapshot.scope_key, &snapshot.fork_hash],
    )
}

pub fn entity_id_from_hash_material(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
    for salt in 0_u64..=u64::MAX {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&salt.to_le_bytes());
        for part in parts {
            write_hash_len(&mut hasher, part.len())?;
            hasher.update(part);
        }
        let hash = hasher.finalize();
        let mut id = [0_u8; ENTITY_ID_LEN];
        id.copy_from_slice(&hash.as_bytes()[..ENTITY_ID_LEN]);
        if let Ok(id) = EntityId::from_bytes(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "codebase deterministic entity id exhausted salt space",
    ))
}

/// OF-222 (FIX 2768) archive seam: the ASSET a snapshot file's bytes are stored as.
pub fn archive_codebase_asset_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    codebase_asset_entity_id(content_hash)
}
