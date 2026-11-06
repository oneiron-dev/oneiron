//! Core half of `blob_artifact::store_keys`: its store-layer items live in `oneiron_store::blob_artifact::store_keys` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::store_keys::*;

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use heed::RoTxn;
use rmpv::Value;

/// Asset refcount marker. Key: bytes32 (content hash) + id16 (artifact id).
///
/// The key-byte builders below stay `Vec<u8>`-returning (rather than folding into this table's
/// key type) because `ports::lmdb_aux` also builds these exact keys for its own raw
/// `vault_meta` puts/deletes — a door this module does not own and cannot change.
pub(super) const ASSET_REF: SideTable<([u8; BLOB_ARTIFACT_CONTENT_HASH_LEN], EntityId), (), Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ASSET_REF);

/// Shared with `ports::lmdb_aux`'s raw asset-refcount puts/deletes — this module does not own
/// that door, so this stays a `Vec<u8>` builder off [`side_table::BLOB_ARTIFACT_ASSET_REF`]'s own
/// declared prefix rather than folding into [`ASSET_REF`]'s key type.
pub(crate) fn blob_artifact_asset_ref_prefix(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Vec<u8> {
    let prefix = side_table::BLOB_ARTIFACT_ASSET_REF.prefix;
    let mut key = Vec::with_capacity(prefix.len() + BLOB_ARTIFACT_CONTENT_HASH_LEN + ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(content_hash);
    key
}

pub(crate) fn blob_artifact_asset_ref_key(
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    artifact_id: &EntityId,
) -> Vec<u8> {
    let mut key = blob_artifact_asset_ref_prefix(content_hash);
    key.extend_from_slice(artifact_id.as_bytes());
    key
}

pub(crate) fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, rtxn, id)? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != expected_type {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            context,
        )));
    }
    Ok(())
}
