//! Strict MessagePack framing for blob version records.

use rmpv::Value;

use crate::error::{ArtifactError, Error, Result};

use super::body::{
    BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES, BLOB_ARTIFACT_NAME_MAX_BYTES, validate_text_field,
};
use super::provenance::{BlobVersionProvenance, validate_provenance};
use super::store_keys::{encode_value, entity_value, hash_from_value, read_value, u64_value};
use super::versions::{
    BLOB_ARTIFACT_VERSION_RECORD_KEYS, BlobArtifactVersion, CalcEngineStamp, KEY_CALC_ENGINE,
    KEY_CALC_ENGINE_VERSION, KEY_CLAIM_ID, KEY_CONTENT_HASH, KEY_CREATED_AT, KEY_EXPORT_MEDIA_TYPE,
    KEY_EXPORT_NAME, KEY_FORK_OF_VERSION, KEY_PARENT_VERSION, KEY_PROVENANCE, KEY_RUN_REF,
    KEY_VERSION,
};

pub(super) fn encode_blob_artifact_version_record(record: &BlobArtifactVersion) -> Result<Vec<u8>> {
    let mut entries = vec![
        (
            Value::from(KEY_VERSION),
            Value::Integer(record.version.into()),
        ),
        (
            Value::from(KEY_CONTENT_HASH),
            Value::Binary(record.content_hash.to_vec()),
        ),
        (
            Value::from(KEY_PROVENANCE),
            Value::from(record.provenance.as_str()),
        ),
        (
            Value::from(KEY_RUN_REF),
            record.provenance.run_ref().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_CLAIM_ID),
            Value::Binary(record.claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::Integer(record.created_at.into()),
        ),
        (
            Value::from(KEY_CALC_ENGINE),
            record
                .calc_engine
                .as_ref()
                .map_or(Value::Nil, |s| Value::from(s.engine())),
        ),
        (
            Value::from(KEY_CALC_ENGINE_VERSION),
            record
                .calc_engine
                .as_ref()
                .map_or(Value::Nil, |s| Value::from(s.version())),
        ),
        (
            Value::from(KEY_EXPORT_NAME),
            Value::from(record.export_name.as_str()),
        ),
        (
            Value::from(KEY_EXPORT_MEDIA_TYPE),
            Value::from(record.export_media_type.as_str()),
        ),
    ];
    if let Some(parent) = record.parent_version {
        entries.push((
            Value::from(KEY_PARENT_VERSION),
            Value::Integer(parent.into()),
        ));
    }
    if let Some(fork) = record.fork_of_version {
        entries.push((
            Value::from(KEY_FORK_OF_VERSION),
            Value::Integer(fork.into()),
        ));
    }
    encode_value(
        &Value::Map(entries),
        "blob artifact version MessagePack encode failed",
    )
}

pub(super) fn decode_blob_artifact_version_record(bytes: &[u8]) -> Result<BlobArtifactVersion> {
    let value = read_value(bytes, "version record")?;
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "version record must be a MessagePack map",
        )));
    };

    let mut version = None;
    let mut content_hash = None;
    let mut provenance_kind: Option<String> = None;
    let mut run_ref: Option<Option<String>> = None;
    let mut claim_id = None;
    let mut created_at = None;
    let mut export_name = None;
    let mut export_media_type = None;
    let mut parent_version = None;
    let mut fork_of_version = None;
    let mut calc_engine: Option<Option<String>> = None;
    let mut calc_engine_version: Option<Option<String>> = None;
    let mut seen = [false; BLOB_ARTIFACT_VERSION_RECORD_KEYS.len()];

    for (key, value) in &entries {
        let key = key
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "version record keys must be strings",
            )))?;
        let Some(index) = BLOB_ARTIFACT_VERSION_RECORD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "version record key is not in the pinned BLOB_ARTIFACT_VERSION_RECORD_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "duplicate version record key",
            )));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_VERSION_RECORD_KEYS[index] {
            KEY_VERSION => version = Some(u64_value(value, "version")?),
            KEY_CONTENT_HASH => content_hash = Some(hash_from_value(value, "content_hash")?),
            KEY_PROVENANCE => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidBlobArtifactBody("provenance must be a UTF-8 string"),
                ))?;
                provenance_kind = Some(text.to_owned());
            }
            KEY_RUN_REF => {
                run_ref = Some(match value {
                    Value::Nil => None,
                    other => Some(
                        other
                            .as_str()
                            .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                                "run_ref must be a UTF-8 string or nil",
                            )))?
                            .to_owned(),
                    ),
                });
            }
            KEY_CLAIM_ID => claim_id = Some(entity_value(value, "claim_id")?),
            KEY_CREATED_AT => created_at = Some(u64_value(value, "created_at")?),
            KEY_EXPORT_NAME => {
                export_name = Some(
                    value
                        .as_str()
                        .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                            "export_name must be a UTF-8 string",
                        )))?
                        .to_owned(),
                );
            }
            KEY_EXPORT_MEDIA_TYPE => {
                export_media_type = Some(
                    value
                        .as_str()
                        .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                            "export_media_type must be a UTF-8 string",
                        )))?
                        .to_owned(),
                );
            }
            KEY_PARENT_VERSION => parent_version = Some(u64_value(value, "parent_version")?),
            KEY_FORK_OF_VERSION => fork_of_version = Some(u64_value(value, "fork_of_version")?),
            KEY_CALC_ENGINE | KEY_CALC_ENGINE_VERSION => {
                let text = match value {
                    Value::Nil => None,
                    other => Some(
                        other
                            .as_str()
                            .ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                                "calc stamp must be a UTF-8 string or nil",
                            )))?
                            .to_owned(),
                    ),
                };
                if key == KEY_CALC_ENGINE {
                    calc_engine = Some(text);
                } else {
                    calc_engine_version = Some(text);
                }
            }
            _ => unreachable!("index resolved from BLOB_ARTIFACT_VERSION_RECORD_KEYS"),
        }
    }

    let version = version.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
        "missing required version record key version",
    )))?;
    if version == 0 {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "version record version must be at least 1",
        )));
    }
    if parent_version.is_some_and(|parent| parent == 0 || parent >= version)
        || fork_of_version.is_some_and(|fork| Some(fork) != parent_version)
    {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "invalid blob artifact version parent/fork pointer",
        )));
    }
    let provenance = BlobVersionProvenance::from_parts(
        &provenance_kind.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key provenance",
        )))?,
        run_ref.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key run_ref",
        )))?,
    )?;
    validate_provenance(&provenance)?;
    let calc_engine = match (
        calc_engine.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing calc_engine",
        )))?,
        calc_engine_version.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing calc_engine_version",
        )))?,
    ) {
        (Some(engine), Some(version)) => Some(CalcEngineStamp::new(engine, version)?),
        (None, None) => None,
        _ => {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "calc stamp must have both engine and version",
            )));
        }
    };
    let export_name = export_name.ok_or(Error::Artifact(
        ArtifactError::InvalidBlobArtifactBody("missing required export_name"),
    ))?;
    let export_media_type = export_media_type.ok_or(Error::Artifact(
        ArtifactError::InvalidBlobArtifactBody("missing required export_media_type"),
    ))?;
    validate_text_field(
        &export_name,
        BLOB_ARTIFACT_NAME_MAX_BYTES,
        "invalid export_name",
    )?;
    validate_text_field(
        &export_media_type,
        BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES,
        "invalid export_media_type",
    )?;
    Ok(BlobArtifactVersion {
        version,
        content_hash: content_hash.ok_or(Error::Artifact(
            ArtifactError::InvalidBlobArtifactBody(
                "missing required version record key content_hash",
            ),
        ))?,
        provenance,
        calc_engine,
        claim_id: claim_id.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key claim_id",
        )))?,
        created_at: created_at.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required version record key created_at",
        )))?,
        parent_version,
        fork_of_version,
        export_name,
        export_media_type,
    })
}
