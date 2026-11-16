//! Domain-separated entity identifiers for immutable snapshot assets and manifests.

use crate::code_snapshot::snapshot::CODEBASE_CONTENT_HASH_LEN;
use crate::code_snapshot::snapshot::CodebaseSnapshot;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::fingerprint::purposes;

pub fn codebase_asset_entity_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    EntityId::derive_legacy_material(purposes::code::CODEBASE_ASSET, &[content_hash])
}

/// The immutable capture's CODE id (FIX 4299): its scope, its file
/// manifest and its source revision. The scope no longer holds the commit,
/// so the canonical repo_ref, which does, keeps one capture per revision.
pub fn codebase_snapshot_entity_id(snapshot: &CodebaseSnapshot) -> Result<EntityId> {
    EntityId::derive_legacy_material(
        purposes::code::CODEBASE_SNAPSHOT,
        &[
            &snapshot.scope_key,
            &snapshot.fork_hash,
            snapshot.repo_ref.canonical().as_bytes(),
        ],
    )
}

/// OF-222 (FIX 2768) archive seam: the ASSET a snapshot file's bytes are stored as.
pub fn archive_codebase_asset_id(
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<EntityId> {
    codebase_asset_entity_id(content_hash)
}
