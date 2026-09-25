//! Blob vault_meta key builders and shared MessagePack scalar helpers.

use heed::RoTxn;
use rmpv::Value;

use crate::batch::EntityMetadataHeader;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

pub(super) const BLOB_ARTIFACT_ASSET_ID_DOMAIN: &[u8] = b"oneiron:blob-artifact-asset:v1";

pub const BLOB_ARTIFACT_CONTENT_HASH_LEN: usize = 32;

pub const BLOB_ARTIFACT_RUN_REF_MAX_BYTES: usize = 1024;

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

pub(super) fn read_value(bytes: &[u8], context: &'static str) -> Result<Value> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidBlobArtifactBody(match context {
            "body" => "body is not valid MessagePack",
            _ => "version record is not valid MessagePack",
        }))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            match context {
                "body" => "trailing bytes after body map",
                _ => "trailing bytes after version record map",
            },
        )));
    }
    Ok(value)
}

pub(super) fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub(super) fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            field,
        )));
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Artifact(ArtifactError::InvalidBlobArtifactBody(field)))?;
    EntityId::from_bytes(raw)
        .map_err(|_| Error::Artifact(ArtifactError::InvalidBlobArtifactBody(field)))
}

pub(super) fn hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            field,
        )));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Artifact(ArtifactError::InvalidBlobArtifactBody(field)))
}

pub(super) fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value
        .as_u64()
        .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            field,
        )))
}

pub(crate) fn require_entity_type(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    expected_type: u8,
    context: &'static str,
) -> Result<()> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
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
