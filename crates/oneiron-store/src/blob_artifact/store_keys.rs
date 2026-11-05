//! Blob vault_meta key builders and shared MessagePack scalar helpers.

use heed::RoTxn;
use rmpv::Value;

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::EntityMetadataHeader;

pub const BLOB_ARTIFACT_ASSET_ID_DOMAIN: &[u8] = b"oneiron:blob-artifact-asset:v1";

pub const BLOB_ARTIFACT_CONTENT_HASH_LEN: usize = 32;

pub const BLOB_ARTIFACT_RUN_REF_MAX_BYTES: usize = 1024;

pub fn read_value(bytes: &[u8], context: &'static str) -> Result<Value> {
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

pub fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
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

pub fn hash_from_value(
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

pub fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value
        .as_u64()
        .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            field,
        )))
}
