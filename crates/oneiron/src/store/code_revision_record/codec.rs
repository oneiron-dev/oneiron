//! Core half of `store::code_revision_record::codec`: its store-layer items live in `oneiron_store::code_revision_record::codec` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::code_revision_record::codec::*;

use super::types::{CodeRevision, CodeRevisionFork, CodeRevisionKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use crate::side_table::{CodecError, RawValue};
use rmpv::Value;

/// The side table's declared codec is `Raw`: a code revision's on-disk shape is the hand-rolled
/// MessagePack map [`encode_code_revision`]/[`decode_code_revision`] have always spelled.
impl RawValue for CodeRevision {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_code_revision(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_code_revision(bytes)?)
    }
}

/// The side table's declared codec is `Raw`, for the same reason: [`encode_code_revision_fork`]/
/// [`decode_code_revision_fork`] already spell this row's on-disk shape.
impl RawValue for CodeRevisionFork {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_code_revision_fork(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_code_revision_fork(bytes)?)
    }
}

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
        (
            Value::from(KEY_COMMIT_METADATA),
            super::commit_metadata::to_value(revision.commit_metadata.as_ref()),
        ),
        (
            Value::from(KEY_FILE_FRONTIERS),
            super::file_frontiers::to_value(revision)?,
        ),
        (
            Value::from(KEY_BLOB_FRONTIERS),
            super::tree_codec::blobs_to_value(&revision.blob_frontiers),
        ),
        (
            Value::from(KEY_TESTED_QUEUE),
            super::tree_codec::tested_to_value(revision.tested_queue.as_ref())?,
        ),
        (
            Value::from(KEY_SNAPSHOT_ANCHOR),
            optional_entity_value(revision.snapshot_anchor),
        ),
        (
            Value::from(KEY_RETIRED_PATHS),
            super::tree_codec::retirements_to_value(&revision.retired_paths)?,
        ),
    ]);
    encode_value(&value, "code revision MessagePack encode failed")
}

pub fn decode_code_revision(bytes: &[u8]) -> Result<CodeRevision> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after code revision map",
        )));
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
        Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision fork is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "trailing bytes after code revision fork map",
        )));
    }
    decode_code_revision_fork_value(&value)
}

fn decode_code_revision_value(value: &Value) -> Result<CodeRevision> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision must be a MessagePack map",
        )));
    };
    let mut revision_id = None;
    let mut kind = None;
    let mut session_id = None;
    let mut parent_revision_id = None;
    let mut reverted_to_revision_id = None;
    let mut provenance_claim_id = None;
    let mut finalized_at = None;
    let mut file_frontiers = None;
    let mut commit_metadata = None;
    let mut blob_frontiers = None;
    let mut tested_queue = None;
    let mut snapshot_anchor = None;
    let mut retired_paths = None;
    let mut seen = [false; CODE_REVISION_RECORD_KEYS.len()];

    for (key, value) in entries {
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision keys must be strings",
            )))?;
        let Some(index) = CODE_REVISION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision key is not in the pinned CODE_REVISION_RECORD_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate code revision key",
            )));
        }
        seen[index] = true;

        match CODE_REVISION_RECORD_KEYS[index] {
            KEY_REVISION_ID => revision_id = Some(entity_value(value, "revision_id")?),
            KEY_KIND => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidCodeArtifactBody(
                        "code revision kind must be a UTF-8 string",
                    ),
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
            KEY_COMMIT_METADATA => {
                commit_metadata = Some(super::commit_metadata::from_value(value)?);
            }
            KEY_FILE_FRONTIERS => file_frontiers = Some(super::file_frontiers::from_value(value)?),
            KEY_BLOB_FRONTIERS => {
                blob_frontiers = Some(super::tree_codec::blobs_from_value(value)?);
            }
            KEY_TESTED_QUEUE => tested_queue = Some(super::tree_codec::tested_from_value(value)?),
            KEY_SNAPSHOT_ANCHOR => {
                snapshot_anchor = Some(optional_entity_from_value(value, "snapshot_anchor")?);
            }
            KEY_RETIRED_PATHS => {
                retired_paths = Some(super::tree_codec::retirements_from_value(value)?);
            }
            _ => unreachable!("index resolved from CODE_REVISION_RECORD_KEYS"),
        }
    }

    let revision = CodeRevision {
        commit_metadata: commit_metadata
            .ok_or(Error::InvalidClaimBody("missing commit_metadata"))?,
        file_frontiers: file_frontiers.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing file_frontiers"),
        ))?,
        revision_id: revision_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision key revision_id",
        )))?,
        kind: kind.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision key kind",
        )))?,
        session_id: session_id.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision key session_id",
        )))?,
        parent_revision_id: parent_revision_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision key parent_revision_id",
            ),
        ))?,
        reverted_to_revision_id: reverted_to_revision_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision key reverted_to_revision_id",
            ),
        ))?,
        provenance_claim_id: provenance_claim_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision key provenance_claim_id",
            ),
        ))?,
        finalized_at: finalized_at.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision key finalized_at",
            ),
        ))?,
        blob_frontiers: blob_frontiers.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing blob_frontiers"),
        ))?,
        tested_queue: tested_queue.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing tested_queue"),
        ))?,
        snapshot_anchor: snapshot_anchor.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing snapshot_anchor"),
        ))?,
        retired_paths: retired_paths.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody("missing retired_paths"),
        ))?,
    };
    validate_code_revision_shape(&revision)?;
    Ok(revision)
}

fn decode_code_revision_fork_value(value: &Value) -> Result<CodeRevisionFork> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision fork must be a MessagePack map",
        )));
    };
    let mut fork_session_id = None;
    let mut parent_session_id = None;
    let mut base_revision_id = None;
    let mut forked_at = None;
    let mut seen = [false; CODE_REVISION_FORK_KEYS.len()];

    for (key, value) in entries {
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision fork keys must be strings",
            )))?;
        let Some(index) = CODE_REVISION_FORK_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "code revision fork key is not in the pinned CODE_REVISION_FORK_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "duplicate code revision fork key",
            )));
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
        fork_session_id: fork_session_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision fork key fork_session_id",
            ),
        ))?,
        parent_session_id: parent_session_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision fork key parent_session_id",
            ),
        ))?,
        base_revision_id: base_revision_id.ok_or(Error::Artifact(
            ArtifactError::InvalidCodeArtifactBody(
                "missing required code revision fork key base_revision_id",
            ),
        ))?,
        forked_at: forked_at.ok_or(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "missing required code revision fork key forked_at",
        )))?,
    };
    validate_code_revision_fork_shape(&fork)?;
    Ok(fork)
}

pub(crate) fn validate_code_revision_shape(revision: &CodeRevision) -> Result<()> {
    super::commit_metadata::validate(revision)?;
    super::file_frontiers::validate(revision)?;
    super::tree_inventory::CodeTreeInventory::validate_partition(revision)?;
    if revision.parent_revision_id == Some(revision.revision_id)
        || revision.reverted_to_revision_id == Some(revision.revision_id)
    {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision cannot point at itself",
        )));
    }
    match revision.kind {
        CodeRevisionKind::Commit => {
            if revision.reverted_to_revision_id.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "commit code revision must not carry reverted_to_revision_id",
                )));
            }
        }
        CodeRevisionKind::Revert => {
            if revision.parent_revision_id.is_none() || revision.reverted_to_revision_id.is_none() {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "revert code revision requires parent and reverted_to revision ids",
                )));
            }
            if revision.parent_revision_id == revision.reverted_to_revision_id {
                return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                    "revert parent and restored revision must be distinct",
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_code_revision_fork_shape(fork: &CodeRevisionFork) -> Result<()> {
    if fork.fork_session_id == fork.parent_session_id {
        return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
            "code revision fork session cannot be its own parent",
        )));
    }
    Ok(())
}
