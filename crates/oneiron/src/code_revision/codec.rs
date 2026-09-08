//! Pinned body keys, revision/fork encode-decode, shape validators and msgpack scalar accessors.

use rmpv::Value;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

use super::types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};

pub(crate) const CODE_REVISION_CLAIM_PREDICATE: &str = "code.revision";

pub const CODE_REVISION_RECORD_KEYS: [&str; 7] = [
    "revision_id",
    "kind",
    "session_id",
    "parent_revision_id",
    "reverted_to_revision_id",
    "provenance_claim_id",
    "finalized_at",
];

pub const CODE_REVISION_FORK_KEYS: [&str; 4] = [
    "fork_session_id",
    "parent_session_id",
    "base_revision_id",
    "forked_at",
];

pub(super) const KEY_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[0];

const KEY_KIND: &str = CODE_REVISION_RECORD_KEYS[1];

pub(super) const KEY_SESSION_ID: &str = CODE_REVISION_RECORD_KEYS[2];

pub(super) const KEY_PARENT_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[3];

pub(super) const KEY_REVERTED_TO_REVISION_ID: &str = CODE_REVISION_RECORD_KEYS[4];

pub(super) const KEY_PROVENANCE_CLAIM_ID: &str = CODE_REVISION_RECORD_KEYS[5];

pub(super) const KEY_FINALIZED_AT: &str = CODE_REVISION_RECORD_KEYS[6];

const KEY_FORK_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[0];

const KEY_PARENT_SESSION_ID: &str = CODE_REVISION_FORK_KEYS[1];

const KEY_BASE_REVISION_ID: &str = CODE_REVISION_FORK_KEYS[2];

const KEY_FORKED_AT: &str = CODE_REVISION_FORK_KEYS[3];

pub(super) const CODE_REVISION_HASH_LEN: usize = 32;

pub fn encode_code_revision(revision: &CodeRevision) -> Result<Vec<u8>> {
    validate_code_revision_shape(revision)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_REVISION_ID),
            Value::Binary(revision.revision_id.as_bytes().to_vec()),
        ),
        (Value::from(KEY_KIND), Value::from(revision.kind.as_str())),
        (
            Value::from(KEY_SESSION_ID),
            Value::Binary(revision.session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PARENT_REVISION_ID),
            optional_entity_value(revision.parent_revision_id),
        ),
        (
            Value::from(KEY_REVERTED_TO_REVISION_ID),
            optional_entity_value(revision.reverted_to_revision_id),
        ),
        (
            Value::from(KEY_PROVENANCE_CLAIM_ID),
            optional_entity_value(revision.provenance_claim_id),
        ),
        (
            Value::from(KEY_FINALIZED_AT),
            Value::Integer(revision.finalized_at.into()),
        ),
    ]);
    encode_value(&value, "code revision MessagePack encode failed")
}

pub fn decode_code_revision(bytes: &[u8]) -> Result<CodeRevision> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidCodeArtifactBody("code revision is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision map",
        ));
    }
    decode_code_revision_value(&value)
}

pub fn encode_code_revision_fork(fork: &CodeRevisionFork) -> Result<Vec<u8>> {
    validate_code_revision_fork_shape(fork)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_FORK_SESSION_ID),
            Value::Binary(fork.fork_session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_PARENT_SESSION_ID),
            Value::Binary(fork.parent_session_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_BASE_REVISION_ID),
            Value::Binary(fork.base_revision_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_FORKED_AT),
            Value::Integer(fork.forked_at.into()),
        ),
    ]);
    encode_value(&value, "code revision fork MessagePack encode failed")
}

pub fn decode_code_revision_fork(bytes: &[u8]) -> Result<CodeRevisionFork> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::InvalidCodeArtifactBody("code revision fork is not valid MessagePack")
    })?;
    if !cursor.is_empty() {
        return Err(Error::InvalidCodeArtifactBody(
            "trailing bytes after code revision fork map",
        ));
    }
    decode_code_revision_fork_value(&value)
}

fn decode_code_revision_value(value: &Value) -> Result<CodeRevision> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision must be a MessagePack map",
        ));
    };
    let mut revision_id = None;
    let mut kind = None;
    let mut session_id = None;
    let mut parent_revision_id = None;
    let mut reverted_to_revision_id = None;
    let mut provenance_claim_id = None;
    let mut finalized_at = None;
    let mut seen = [false; CODE_REVISION_RECORD_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision key is not in the pinned CODE_REVISION_RECORD_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_RECORD_KEYS[index] {
            KEY_REVISION_ID => revision_id = Some(entity_value(value, "revision_id")?),
            KEY_KIND => {
                let text = value.as_str().ok_or(Error::InvalidCodeArtifactBody(
                    "code revision kind must be a UTF-8 string",
                ))?;
                kind = Some(CodeRevisionKind::parse(text)?);
            }
            KEY_SESSION_ID => session_id = Some(entity_value(value, "session_id")?),
            KEY_PARENT_REVISION_ID => {
                parent_revision_id = Some(optional_entity_from_value(value, "parent_revision_id")?);
            }
            KEY_REVERTED_TO_REVISION_ID => {
                reverted_to_revision_id = Some(optional_entity_from_value(
                    value,
                    "reverted_to_revision_id",
                )?);
            }
            KEY_PROVENANCE_CLAIM_ID => {
                provenance_claim_id =
                    Some(optional_entity_from_value(value, "provenance_claim_id")?);
            }
            KEY_FINALIZED_AT => finalized_at = Some(u64_value(value, "finalized_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_RECORD_KEYS"),
        }
    }

    let revision = CodeRevision {
        revision_id: revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key revision_id",
        ))?,
        kind: kind.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key kind",
        ))?,
        session_id: session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key session_id",
        ))?,
        parent_revision_id: parent_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key parent_revision_id",
        ))?,
        reverted_to_revision_id: reverted_to_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key reverted_to_revision_id",
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key provenance_claim_id",
        ))?,
        finalized_at: finalized_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision key finalized_at",
        ))?,
    };
    validate_code_revision_shape(&revision)?;
    Ok(revision)
}

fn decode_code_revision_fork_value(value: &Value) -> Result<CodeRevisionFork> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision fork must be a MessagePack map",
        ));
    };
    let mut fork_session_id = None;
    let mut parent_session_id = None;
    let mut base_revision_id = None;
    let mut forked_at = None;
    let mut seen = [false; CODE_REVISION_FORK_KEYS.len()];

    for (key, value) in entries {
        let key = key.as_str().ok_or(Error::InvalidCodeArtifactBody(
            "code revision fork keys must be strings",
        ))?;
        let Some(index) = CODE_REVISION_FORK_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidCodeArtifactBody(
                "code revision fork key is not in the pinned CODE_REVISION_FORK_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidCodeArtifactBody(
                "duplicate code revision fork key",
            ));
        }
        seen[index] = true;

        match CODE_REVISION_FORK_KEYS[index] {
            KEY_FORK_SESSION_ID => {
                fork_session_id = Some(entity_value(value, "fork_session_id")?);
            }
            KEY_PARENT_SESSION_ID => {
                parent_session_id = Some(entity_value(value, "parent_session_id")?);
            }
            KEY_BASE_REVISION_ID => {
                base_revision_id = Some(entity_value(value, "base_revision_id")?);
            }
            KEY_FORKED_AT => forked_at = Some(u64_value(value, "forked_at")?),
            _ => unreachable!("index resolved from CODE_REVISION_FORK_KEYS"),
        }
    }

    let fork = CodeRevisionFork {
        fork_session_id: fork_session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key fork_session_id",
        ))?,
        parent_session_id: parent_session_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key parent_session_id",
        ))?,
        base_revision_id: base_revision_id.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key base_revision_id",
        ))?,
        forked_at: forked_at.ok_or(Error::InvalidCodeArtifactBody(
            "missing required code revision fork key forked_at",
        ))?,
    };
    validate_code_revision_fork_shape(&fork)?;
    Ok(fork)
}

pub(super) fn validate_code_revision_shape(revision: &CodeRevision) -> Result<()> {
    if revision.parent_revision_id == Some(revision.revision_id)
        || revision.reverted_to_revision_id == Some(revision.revision_id)
    {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision cannot point at itself",
        ));
    }
    match revision.kind {
        CodeRevisionKind::Commit => {
            if revision.reverted_to_revision_id.is_some() {
                return Err(Error::InvalidCodeArtifactBody(
                    "commit code revision must not carry reverted_to_revision_id",
                ));
            }
        }
        CodeRevisionKind::Revert => {
            if revision.parent_revision_id.is_none() || revision.reverted_to_revision_id.is_none() {
                return Err(Error::InvalidCodeArtifactBody(
                    "revert code revision requires parent and reverted_to revision ids",
                ));
            }
            if revision.parent_revision_id == revision.reverted_to_revision_id {
                return Err(Error::InvalidCodeArtifactBody(
                    "revert parent and restored revision must be distinct",
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_code_revision_fork_shape(fork: &CodeRevisionFork) -> Result<()> {
    if fork.fork_session_id == fork.parent_session_id {
        return Err(Error::InvalidCodeArtifactBody(
            "code revision fork session cannot be its own parent",
        ));
    }
    Ok(())
}

pub(super) fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub(super) fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

pub(super) fn optional_hash_value(hash: Option<[u8; CODE_REVISION_HASH_LEN]>) -> Value {
    hash.map_or(Value::Nil, |hash| Value::Binary(hash.to_vec()))
}

pub(super) fn entity_value(value: &Value, field: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeArtifactBody(field));
    };
    entity_from_bytes(bytes, field)
}

pub(super) fn optional_entity_from_value(
    value: &Value,
    field: &'static str,
) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => entity_from_bytes(bytes, field).map(Some),
        _ => Err(Error::InvalidCodeArtifactBody(field)),
    }
}

fn entity_from_bytes(bytes: &[u8], field: &'static str) -> Result<EntityId> {
    let raw: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidCodeArtifactBody(field))?;
    EntityId::from_bytes(raw).map_err(|_| Error::InvalidCodeArtifactBody(field))
}

pub(super) fn hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<[u8; CODE_REVISION_HASH_LEN]> {
    let Value::Binary(bytes) = value else {
        return Err(Error::InvalidCodeArtifactBody(field));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidCodeArtifactBody(field))
}

pub(super) fn optional_hash_from_value(
    value: &Value,
    field: &'static str,
) -> Result<Option<[u8; CODE_REVISION_HASH_LEN]>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(_) => hash_from_value(value, field).map(Some),
        _ => Err(Error::InvalidCodeArtifactBody(field)),
    }
}

pub(super) fn u64_value(value: &Value, field: &'static str) -> Result<u64> {
    value.as_u64().ok_or(Error::InvalidCodeArtifactBody(field))
}
