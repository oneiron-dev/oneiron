//! The id a sync peer knows a marked snapshot ASSET's copy by (FIX 7608
//! slice 4), derived from the source id alone under the copy rules.
//!
//! It is featureless: a source erase derives it in every build to reach the
//! rows kept under it (FIX 10798; owner ruling KEY STORE = A). Deriving it
//! reads nothing, so an erase with no copy never fails on it.

use crate::entity_id::EntityId;
use crate::error::Result;

/// The rules a sync copy and its id are made by (CALL 4-I, ruling (e),
/// Engine 10-22 07:20). Part of every copy id and generation, so a change
/// to them is a new copy everywhere.
pub(crate) const REPO_SYNC_PROJECTION_SCHEMA: u16 = 1;

/// The domain a copy id is derived in.
const COPY_ID_CONTEXT: &str = "oneiron.repo-sync-projection.copy-id.v1";

/// The copy id of the marked snapshot ASSET `source`: an ASSET id (the
/// codebase derivation) over a digest of the rules and the source id. One
/// source, one copy id, for every generation of its copy.
///
/// # Errors
/// The codebase derivation's own failure.
pub(crate) fn copy_id(source: &EntityId) -> Result<EntityId> {
    let mut material = Vec::with_capacity(2 + 16);
    material.extend_from_slice(&REPO_SYNC_PROJECTION_SCHEMA.to_be_bytes());
    material.extend_from_slice(source.as_bytes());
    crate::codebase::snapshot_asset_entity_id(&blake3::derive_key(COPY_ID_CONTEXT, &material))
}
