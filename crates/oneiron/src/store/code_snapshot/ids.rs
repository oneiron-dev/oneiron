//! Domain-separated entity identifiers for immutable snapshot assets and manifests.

use super::snapshot::write_hash_len;
use super::{CODEBASE_CONTENT_HASH_LEN, CodebaseSnapshot};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

const CODEBASE_ASSET_ID_DOMAIN: &[u8] = b"oneiron:codebase-asset-entity:v1";

const CODEBASE_SNAPSHOT_ID_DOMAIN: &[u8] = b"oneiron:codebase-snapshot-entity:v1";

pub(crate) fn codebase_asset_entity_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    entity_id_from_hash_material(CODEBASE_ASSET_ID_DOMAIN, &[content_hash])
}

pub(crate) fn codebase_snapshot_entity_id(snapshot: &CodebaseSnapshot) -> Result<EntityId> {
    entity_id_from_hash_material(
        CODEBASE_SNAPSHOT_ID_DOMAIN,
        &[&snapshot.scope_key, &snapshot.fork_hash],
    )
}

pub(crate) fn entity_id_from_hash_material(domain: &[u8], parts: &[&[u8]]) -> Result<EntityId> {
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
pub(crate) fn archive_codebase_asset_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    codebase_asset_entity_id(content_hash)
}
