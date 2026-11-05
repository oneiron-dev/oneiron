//! Pinned body keys, revision/fork encode-decode, shape validators and msgpack scalar accessors.

use rmpv::Value;

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::ENTITY_ID_LEN;
use oneiron_contracts::entity_id::EntityId;

use oneiron_base::error::ArtifactError;

pub const CODE_REVISION_CLAIM_PREDICATE: &str = "code.revision";

pub const CODE_REVISION_RECORD_KEYS: [&str; 13] = [
    "revision_id",
    "kind",
    "session_id",
    "parent_revision_id",
    "reverted_to_revision_id",
    "provenance_claim_id",
    "finalized_at",
    "file_frontiers",
    "commit_metadata",
    "blob_frontiers",
    "tested_queue",
    "snapshot_anchor",
    "retired_paths",
];

pub const CODE_REVISION_FORK_KEYS: [&str; 4] = [
    "fork_session_id",
    "parent_session_id",
    "base_revision_id",
    "forked_at",
];

pub const KEY_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[0];

pub const KEY_KIND: &str = CODE_REVISION_RECORD_KEYS[1];

pub const KEY_SESSION_ID: &str = CODE_REVISION_RECORD_KEYS[2];

pub const KEY_PARENT_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[3];

pub const KEY_REVERTED_TO_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[4];

pub const KEY_PROVENANCE_CLAIM_ID: &str = CODE_REVISION_RECORD_KEYS[5];

pub const KEY_FINALIZED_AT: &str = CODE_REVISION_RECORD_KEYS[6];

pub const KEY_COMMIT_METADATA: &str = CODE_REVISION_RECORD_KEYS[8];

pub const KEY_FILE_FRONTIERS: &str = CODE_REVISION_RECORD_KEYS[7];

pub const KEY_BLOB_FRONTIERS: &str = CODE_REVISION_RECORD_KEYS[9];

pub const KEY_TESTED_QUEUE: &str = CODE_REVISION_RECORD_KEYS[10];

pub const KEY_SNAPSHOT_ANCHOR: &str = CODE_REVISION_RECORD_KEYS[11];

pub const KEY_RETIRED_PATHS: &str = CODE_REVISION_RECORD_KEYS[12];

pub const KEY_FORK_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[0];

pub const KEY_PARENT_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[1];

pub const KEY_BASE_REVISION_ID: &str = CODE_REVISION_FORK_KEYS[2];

pub const KEY_FORKED_AT: &str = CODE_REVISION_FORK_KEYS[3];

pub const CODE_REVISION_HASH_LEN: usize = 32;

pub fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

pub fn optional_hash_value(hash: Option<[u8; CODE_REVISION_HASH_LEN]>) -> Value {
    hash.map_or(Value::Nil, |hash| Value::Binary(hash.to_vec()))
}

pub fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            field,
        )));
    };
    entity_from_bytes(bytes, field)
}

pub fn optional_entity_from_value(value: &Value, field: &'static str) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => entity_from_bytes(bytes, field).map(Some),
        _ => Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            field,
        ))),
    }
}

fn entity_from_bytes(bytes: &[u8], field: &'static str) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::Artifact(ArtifactError::InvalidCodeArtifactBody(field)))?;
    EntityId::from_bytes(raw)
        .map_err(|_| Error::Artifact(ArtifactError::InvalidCodeArtifactBody(field)))
}

pub fn hash_from_value(value: &Value, field: &'static str) -> Result<[u8; CODE_REVISION_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            field,
        )));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Artifact(ArtifactError::InvalidCodeArtifactBody(field)))
}

pub fn optional_hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<Option<[u8; CODE_REVISION_HASH_LEN]>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(_) => hash_from_value(value, field).map(Some),
        _ => Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            field,
        ))),
    }
}

pub fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value
        .as_u64()
        .ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            field,
        )))
}
